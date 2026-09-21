#!/usr/bin/env python3
"""
HATLS v0.2 — Hybrid Attested TLS with a Continuity Mandate.

A RATS continuity layer that sits above a transport binder. The binder proves "this TLS session
talks to a TEE"; the continuity layer proves "and it is still the SAME enrolled instance, in an
unbroken order, and here is what happens when it is not".

  intra_link  = HKDF(transcript_checkpoint, TIK_pub)         # the early binder, public transcript
  post_link_n = HKDF(exporter, prev_link || counter_n)       # the post binder, shared secret + order
  Evidence_n  : a TEE report whose REPORT_DATA = SHA-512("HATLS-continuity-v0" || post_link_n)
  Mandate     : an authority over an identity. It admits ONE continuous, ordered, anchor-consistent
                chain per identity, and names the impostor instead of destroying the identity.

Three rules this version enforces that v0.1 did not (see docs/AUDIT.md):
  1. ENROLMENT BINDS THE KEY. The enrolment report must cover a PKCS#10 CSR that carries the very
     public key being enrolled and is self-signed by its private key (proof of possession), against
     a nonce the mandate itself issued. Enrolment is first-write-wins.
  2. THE ANCHOR MUST EXIST. A platform that reports no usable instance anchor (e.g. an all-zero
     SEV-SNP CHIP_ID under a shared-tenancy VLEK) FAILS CLOSED. It never silently compares equal.
  3. AN IMPOSTOR CANNOT REVOKE THE VICTIM. Evidence from the wrong anchor rejects the presenter and
     records contention. Revocation is an explicit, operator-driven act.

This module is transport- and TEE-agnostic. The TEE is injected: `tee.report(report_data)` returns
signed Evidence; `verify_report(evidence, expected_report_data) -> (ok, anchor)` checks it, where
`anchor` is None when the platform exposes no usable instance identifier.
"""
import hashlib, hmac, time
from .store import MemoryStore

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

# ---------- enrolment credential: a real CSR, self-signed (proof of possession) -------
def make_enrolment_csr(tik_private_key, subject_cn="hatls-identity"):
    """Build the PKCS#10 CSR that the chip will sign over. Self-signed by the identity key, so it
    is itself the proof that whoever asks for enrolment holds the private half."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
           .sign(tik_private_key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.DER)

def csr_public_key_der(csr_der):
    """Return the SPKI DER carried by the CSR, but ONLY if the CSR's own signature verifies.
    Raises on a malformed CSR or a CSR whose signature does not match its public key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    csr = x509.load_der_x509_csr(csr_der)
    if not csr.is_signature_valid:
        raise ValueError("CSR signature invalid: no proof of possession")
    return csr.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

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
class NoAnchor(Exception):
    """The platform exposes no usable instance anchor, so continuity-to-an-instance is undecidable."""

class Mandate:
    """Admits one continuous, ordered, anchor-consistent chain per identity.

    Three settings decide what is actually guaranteed, and all three are explicit on purpose.

    `require_anchor=True` (default) refuses a platform that cannot name its own instance, rather
    than silently accepting one. `require_anchor=False` degrades to ordering and freshness only:
    replay and relay are still caught, RE-HOSTING IS NOT.

    `require_enrolment=False` (default) lets an identity be served with no enrolment on record, in
    which case a second instance is recorded as contention rather than refused. `True` refuses any
    identity the ledger does not know. Set it wherever the enrolment gate is the guarantee you are
    relying on: without it, an empty ledger and a deliberately unenrolled identity look identical.

    `store` holds the ledger -- enrolment, revocation, contention. The default `MemoryStore` is NOT
    durable, so a restart loses it. Pass a `FileStore` for a mandate whose answers must survive the
    process. Session chains are deliberately not stored: a connection dies with the process, and
    the next one starts its own chain.

    The mandate itself is trusted, and is not part of the threat model in docs/THREAT-MODEL.md.
    """
    def __init__(self, verify_report, require_anchor=True, require_enrolment=False,
                 store=None, challenge_ttl=300):
        self.verify_report = verify_report
        self.require_anchor = require_anchor
        self.require_enrolment = require_enrolment
        self.store = store if store is not None else MemoryStore()
        self.challenge_ttl = challenge_ttl
        self.sessions = {}     # (tik_pub_hex, session_key) -> {"prev":.., "counter":int}  ephemeral
        self._challenges = {}  # nonce -> expiry                                            ephemeral
        self.log = []

    # ---- the durable ledger -------------------------------------------------------
    _BLANK = {"enrolled_anchor": None, "observed_anchor": None,
              "revoked": False, "reason": None, "contention": []}

    def _rec(self, k):
        r = self.store.get(k)
        return dict(self._BLANK) if r is None else {**self._BLANK, **r}

    def _save(self, k, rec): self.store.put(k, rec)

    @property
    def durable(self): return getattr(self.store, "durable", False)

    @property
    def enrolled(self):
        out = {}
        for k in self.store.keys():
            a = (self.store.get(k) or {}).get("enrolled_anchor")
            if a: out[k] = bytes.fromhex(a)
        return out

    @property
    def identity(self):
        out = {}
        for k in self.store.keys():
            r = self.store.get(k) or {}
            a = r.get("observed_anchor")
            out[k] = {"anchor": bytes.fromhex(a) if a else None, "revoked": r.get("revoked", False)}
        return out

    @property
    def contention(self):
        out = {}
        for k in self.store.keys():
            c = (self.store.get(k) or {}).get("contention") or []
            if c: out[k] = c
        return out

    def _emit(self, ev): self.log.append(ev)

    def _dispute(self, k, reason):
        rec = self._rec(k); rec["contention"] = (rec["contention"] + [reason])[-64:]
        self._save(k, rec)

    # ---- challenge/response: the mandate picks the nonce, and it expires ----
    def challenge(self):
        import os as _os
        n = _os.urandom(32)
        now = time.time()
        self._challenges = {x: e for x, e in self._challenges.items() if e > now}   # drop stale
        self._challenges[n] = now + self.challenge_ttl
        return n

    def enroll(self, tik_pub, enroll_evidence, nonce, csr_der):
        """One-time: bind an identity key to the instance it was born on.

        Requires (a) a nonce this mandate issued, unspent and unexpired, (b) a CSR that carries
        EXACTLY tik_pub and is self-signed by its private half, (c) a TEE report over
        SHA-512(nonce || CSR) from a platform with a usable anchor. First write wins."""
        k = tik_pub.hex()
        expiry = self._challenges.get(nonce)
        if expiry is None:
            self._emit(("enroll-rejected", k[:16], "stale or unissued nonce"))
            return False, "nonce was not issued by this mandate (replay)"
        if expiry <= time.time():
            del self._challenges[nonce]
            self._emit(("enroll-rejected", k[:16], "nonce expired"))
            return False, "nonce expired"
        rec = self._rec(k)
        if rec["enrolled_anchor"] is not None:
            self._emit(("enroll-rejected", k[:16], "already enrolled"))
            return False, "identity already enrolled; re-enrolment is an operator action"
        try:
            csr_spki = csr_public_key_der(csr_der)
        except Exception as e:
            self._emit(("enroll-rejected", k[:16], f"bad CSR: {e}"))
            return False, f"CSR unusable: {e}"
        if csr_spki != tik_pub:
            self._emit(("enroll-rejected", k[:16], "CSR carries a different key"))
            return False, "CSR does not carry the key being enrolled"
        expected_rd = hashlib.sha512(nonce + csr_der).digest()
        ok, anchor = self.verify_report(enroll_evidence, expected_rd)
        if not ok:
            self._emit(("enroll-rejected", k[:16], "evidence invalid"))
            return False, "enrolment evidence invalid"
        if anchor is None:
            self._emit(("enroll-rejected", k[:16], "platform exposes no instance anchor"))
            return False, ("platform exposes no usable instance anchor (masked CHIP_ID): "
                           "continuity-to-an-instance cannot be enrolled here")
        del self._challenges[nonce]
        rec["enrolled_anchor"] = anchor.hex()
        self._save(k, rec)
        self._emit(("enrolled", k[:16], anchor.hex()[:12]))
        return True, "enrolled"

    def revoke(self, tik_pub, reason="operator"):
        """Explicit, deliberate revocation. Nothing an unauthenticated presenter does reaches here."""
        k = tik_pub.hex()
        rec = self._rec(k); rec["revoked"] = True; rec["reason"] = reason
        self._save(k, rec)
        self._emit(("revoked", k[:16], reason))
        return True, f"identity revoked: {reason}"

    def present(self, tik_pub, session_context, exporter, msg):
        """Appraise one attestation step.

        `session_context` and `exporter` MUST both be derived by the Relying Party from ITS OWN
        side of the TLS session (see hatls.client). Values copied out of the peer's message prove
        nothing: a relay forwards them unchanged.

        There is no `new_session` flag. Which chain a step belongs to is DERIVED from the session
        context, so the caller cannot assert its way past the counter. Continuity is tracked per
        connection; the ledger -- anchor, enrolment, revocation, contention -- is per identity and
        may be durable.

        Returns (accepted, reason). A rejected presenter never revokes the identity it claims."""
        k = tik_pub.hex()
        skey = hashlib.sha256(session_context).hexdigest()[:32]
        rec = self._rec(k)
        if rec["revoked"]:
            self._emit(("declined-revoked", k[:16], msg["counter"]))
            return False, "identity revoked"

        # 1) the hardware Evidence must be valid AND bind exactly this post_link
        pl = bytes.fromhex(msg["post_link"])
        ok, anchor = self.verify_report(msg["evidence"], report_data_for(pl))
        if not ok:
            self._emit(("declined-evidence", k[:16], msg["counter"]))
            return False, "evidence invalid or does not bind the link"

        # 1a) FAIL CLOSED on a platform that cannot name its own instance. An all-zero anchor is
        #     not an identity: on such a platform every machine looks alike, so accepting it would
        #     silently hand out a guarantee we cannot keep.
        if anchor is None:
            if self.require_anchor:
                self._emit(("declined-no-anchor", k[:16], msg["counter"]))
                return False, ("platform exposes no usable instance anchor: re-hosting is "
                               "undecidable here (set require_anchor=False to accept that)")
            self._emit(("anchor-absent-downgraded", k[:16], msg["counter"]))

        enrolled_anchor = bytes.fromhex(rec["enrolled_anchor"]) if rec["enrolled_anchor"] else None

        # 1b) NO SILENT DOWNGRADE. An empty ledger and a deliberately unenrolled identity look the
        #     same from here, so a deployment that relies on the enrolment gate must say so: a lost
        #     or wiped ledger then refuses service instead of quietly reverting to the weaker mode.
        if enrolled_anchor is None and self.require_enrolment:
            self._emit(("declined-not-enrolled", k[:16], msg["counter"]))
            return False, ("identity has no enrolment on record and this mandate requires one "
                           "(a lost ledger must not silently downgrade the guarantee)")

        # 1c) ENROLMENT GATE. Evidence from any instance other than the enrolled one is an
        #     impostor, rejected on its FIRST message. We know which instance is legitimate, so we
        #     reject the PRESENTER and leave the victim's identity untouched.
        if enrolled_anchor is not None and anchor is not None and anchor != enrolled_anchor:
            self._dispute(k, "evidence from a non-enrolled instance")
            self._emit(("rejected-impostor", k[:16], enrolled_anchor.hex()[:12], anchor.hex()[:12], msg["counter"]))
            return False, "rejected: key presented from an instance it was not enrolled on"

        # 2) Without enrolment we cannot tell owner from thief, so we protect the incumbent and
        #    record a dispute. We do NOT destroy the identity on an unauthenticated claim.
        observed = bytes.fromhex(rec["observed_anchor"]) if rec["observed_anchor"] else None
        if observed is not None and anchor is not None and anchor != observed:
            self._dispute(k, "second instance under one identity")
            self._emit(("contention-anchor", k[:16], observed.hex()[:12], anchor.hex()[:12], msg["counter"]))
            return False, ("continuity contention: a second instance claims this identity "
                           "(no enrolment on record, so the mandate refuses to pick a winner)")

        # 3) the chain of THIS connection. A session we have not seen must start at counter 0; one
        #    we have seen must advance by exactly one.
        sess = self.sessions.get((k, skey))
        if sess is None:
            if msg["counter"] != 0:
                self._emit(("declined-counter", k[:16], "new session", msg["counter"]))
                return False, "a session's first link must be counter 0"
            base = intra_link(session_context, tik_pub)
        else:
            if msg["counter"] != sess["counter"] + 1:
                self._dispute(k, "counter did not advance")
                self._emit(("declined-counter", k[:16], sess["counter"], msg["counter"]))
                return False, "counter did not advance by one (replay or reorder)"
            base = sess["prev"]

        # 4) recompute the link ourselves from values we derived, not values we were handed
        if post_link(exporter, base, msg["counter"]) != pl:
            self._dispute(k, "link does not chain")
            self._emit(("declined-linkmismatch", k[:16], msg["counter"]))
            return False, "link does not chain (relay, replay or a foreign session)"

        self.sessions[(k, skey)] = {"prev": pl, "counter": msg["counter"]}
        if anchor is not None:
            rec["observed_anchor"] = anchor.hex()
            self._save(k, rec)
        self._emit(("accept", k[:16], skey[:8], msg["counter"], (anchor or b"").hex()[:12]))
        return True, "accepted; continuity intact"
