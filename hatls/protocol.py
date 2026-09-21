#!/usr/bin/env python3
"""
HATLS v0 — Hybrid Attested TLS with a Continuity Mandate.

One protocol that unifies the two SEAT camps and adds the piece the WG use-cases (3.8.1, 4.8)
names but nobody specifies: continuity to a platform instance, with revocation on fork.

Design (see HYBRID-DESIGN.md, GAP-ANALYSIS.md):

  intra_link = HKDF(transcript_checkpoint, TIK_pub)          # Camp 1: early, public transcript
  post_link_n = HKDF(exporter, prev_link || counter_n)       # Camp 2: shared secret + order
  Evidence_n : a TEE report whose REPORT_DATA = SHA-512(post_link_n)   # binds the link to HARDWARE
  Mandate    : a ledger keyed by TIK_pub. It admits ONE continuous, ordered, chip-consistent chain.
               A second chip under the same TIK, or a broken/replayed counter, is a FORK -> REVOKE.

This module is transport- and TEE-agnostic. The TEE is injected: `tee.report(report_data)` returns
signed Evidence; `verify_report(...)` checks it. For local debugging we use a MockTEE (an ephemeral
signing key standing in for the AMD SP). On hardware the same calls hit /dev/sev-guest and the VCEK.
"""
import hashlib, hmac, json, time

# ---------- binder maths (RFC 8446 HKDF-Expand-Label shape) --------------------------
def _hkdf_expand_label(secret, label, ctx, n=32, H=hashlib.sha384):
    full = b"tls13 " + label
    info = n.to_bytes(2,"big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    out=t=b""; i=1
    while len(out)<n:
        t = hmac.new(secret, t+info+bytes([i]), H).digest(); out += t; i+=1
    return out[:n]

def intra_link(transcript_hash, tik_pub):
    base = _hkdf_expand_label(bytes(48), b"attestation base", transcript_hash, 48)
    return _hkdf_expand_label(base, b"attestation", hashlib.sha384(tik_pub).digest(), 32)

def post_link(exporter, prev_link, counter):
    return _hkdf_expand_label(exporter, b"continuity", prev_link + counter.to_bytes(8,"big"), 32)

def report_data_for(link):
    return hashlib.sha512(b"HATLS-continuity-v0" + link).digest()   # 64 bytes for REPORT_DATA

# ---------- the Attester side (runs inside the guest/TEE) -----------------------------
class Attester:
    def __init__(self, tee, tik_pub):
        self.tee = tee; self.tik_pub = tik_pub
        self.prev = None; self.counter = 0

    def attest(self, transcript_hash, exporter):
        il = intra_link(transcript_hash, self.tik_pub)
        base = self.prev if self.prev is not None else il
        pl = post_link(exporter, base, self.counter)
        evidence = self.tee.report(report_data_for(pl))     # HARDWARE binds the link
        msg = {"counter": self.counter, "intra_ok_base": self.prev is None,
               "post_link": pl.hex(), "evidence": evidence}
        self.prev = pl; self.counter += 1
        return msg

# ---------- the Mandate (runs at the Relying Party) ----------------------------------
class Mandate:
    """Admits one continuous, ordered, chip-consistent chain per TIK. Forks are revoked."""
    def __init__(self, verify_report):
        self.verify_report = verify_report
        self.state = {}       # tik_pub_hex -> {"chip":.., "prev":.., "counter":.., "revoked":bool}
        self.enrolled = {}    # tik_pub_hex -> chip  (baseline: which chip this key was born on)
        self.log = []

    def enroll(self, tik_pub, enroll_evidence, nonce, csr_der):
        """One-time: the chip signs that THIS key (its CSR) was created on it (TACRA binding:
        REPORT_DATA = SHA-512(nonce || CSR)). The mandate records tik_pub -> chip as the ground
        truth. After this, any Evidence for tik_pub on a different chip is rejected on the FIRST
        message, without needing to see a second (victim) chain -- prevention, not just detection."""
        expected_rd = hashlib.sha512(nonce + csr_der).digest()
        ok, chip = self.verify_report(enroll_evidence, expected_rd)
        if not ok:
            self._emit(("enroll-rejected", tik_pub.hex()[:16])); return False, "enrollment evidence invalid"
        self.enrolled[tik_pub.hex()] = chip
        self._emit(("enrolled", tik_pub.hex()[:16], (chip or b"").hex()[:12]))
        return True, "enrolled"

    def _emit(self, ev): self.log.append(ev)

    def present(self, tik_pub, transcript_hash, exporter, msg, new_session=False):
        """A Relying Party (or a shared mandate service) appraises one attestation step.

        The mandate is a SHARED, append-only authority over an identity, not per-connection state:
        this is what lets it see a stolen key used against a different Relying Party. `new_session`
        marks the first link of a fresh TLS session (a legitimate reconnect starts a new sub-chain).

        Returns (accepted, reason)."""
        k = tik_pub.hex()
        st = self.state.get(k)
        if st and st["revoked"]:
            self._emit(("declined-revoked", k[:16], msg["counter"]))
            return False, "identity already revoked"

        # 1) verify the hardware Evidence and that it binds THIS post_link
        pl = bytes.fromhex(msg["post_link"])
        ok, chip = self.verify_report(msg["evidence"], report_data_for(pl))
        if not ok:
            self._emit(("declined-evidence", k[:16], msg["counter"]))
            return False, "evidence invalid or does not bind the link"

        # 1a) ENROLLMENT GATE (prevention). If this identity was enrolled to a chip, any Evidence
        #     on a different chip is a stolen key, caught on the FIRST message -- no victim needed.
        enrolled_chip = self.enrolled.get(k)
        if enrolled_chip is not None and chip is not None and chip != enrolled_chip:
            self._emit(("blocked-enrollment", k[:16], enrolled_chip.hex()[:12], chip.hex()[:12], msg["counter"]))
            if st: st["revoked"] = True
            return False, "blocked at first message: key presented on a chip it was not enrolled on"

        # 2) the non-copyable anchor: the SAME identity must always be on the SAME chip.
        #    A stolen key on genuine-but-different silicon is a re-host, whatever else checks out.
        if st and chip is not None and st["chip"] is not None and chip != st["chip"]:
            self._emit(("revoke-fork-chip", k[:16], st["chip"].hex()[:12], chip.hex()[:12], msg["counter"]))
            st["revoked"] = True
            return False, "continuity fork: same identity on a different chip (re-hosting)"

        # 3) recompute the post_link ourselves. For a fresh session the base is the intra link of
        #    THIS session; for a continuation it is the previous link we recorded.
        il = intra_link(transcript_hash, tik_pub)
        base = il if (new_session or st is None) else st["prev"]
        expect = post_link(exporter, base, msg["counter"])
        if expect != pl:
            self._emit(("revoke-fork-linkmismatch", k[:16], msg["counter"], (chip or b"").hex()[:12]))
            if st: st["revoked"] = True
            return False, "continuity fork: link does not chain (relay or replay)"

        # 4) within a session the counter advances by exactly one; a fresh session resets to 0
        if st and not new_session and msg["counter"] != st["counter"] + 1:
            self._emit(("revoke-fork-counter", k[:16], st["counter"], msg["counter"]))
            st["revoked"] = True
            return False, "continuity fork: counter did not advance by one (replay)"

        self.state[k] = {"chip": chip, "prev": pl, "counter": msg["counter"], "revoked": False}
        self._emit(("accept", k[:16], msg["counter"], (chip or b"").hex()[:12], "new" if new_session else "cont"))
        return True, "accepted; continuity intact"
