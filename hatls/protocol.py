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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .store import MemoryStore
from .transfer import canonical, verify_grant, GRANT_VERSION
from .log import MerkleLog
from . import receipt as _receipt

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

def report_data_for(link, head=None):
    """What the TEE signs over.

    Without a head this is the v0 binder: the hardware commits to the continuity link and nothing
    else. With one, the hardware ALSO commits to the mandate's claimed ledger state at that moment.

    That second form is the only leverage a relying party has against the authority itself. A log
    makes a mandate's decisions non-repudiable, but the head is still the mandate's own word: it
    can sign two histories and each looks fine alone. Here the head is carried into a report signed
    by a chip the mandate does not own, so an auditor holding that report can say "at this moment
    this mandate claimed this ledger state" and the mandate cannot produce a different one for that
    moment. The party being audited cannot forge the witness."""
    if head is None:
        return hashlib.sha512(b"HATLS-continuity-v0" + link).digest()
    return hashlib.sha512(b"HATLS-continuity-v1" + link + head).digest()

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

    def attest(self, transcript_hash, exporter, head=None):
        """`head` is the relying party's current ledger head, if it sent one. Binding it makes the
        hardware a witness to what the mandate claimed its log was at this moment."""
        il = intra_link(transcript_hash, self.tik_pub)
        base = self.prev if self.prev is not None else il
        pl = post_link(exporter, base, self.counter)
        evidence = self.tee.report(report_data_for(pl, head))   # HARDWARE binds link (+ head)
        msg = {"counter": self.counter, "intra_ok_base": self.prev is None,
               "post_link": pl.hex(), "evidence": evidence}
        if head is not None: msg["head"] = head.hex()
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
                 require_place=False, store=None, challenge_ttl=300, witness_ttl=3600,
                 signing_key=None):
        self.verify_report = verify_report
        # the key the mandate signs its own tree heads with. An ephemeral one makes receipts
        # unverifiable after a restart, so a durable deployment must supply a real one.
        self._signing_key = signing_key or ec.generate_private_key(ec.SECP256R1())
        self.ephemeral_signing_key = signing_key is None
        self.merkle = MerkleLog()
        self.last_receipt = None
        self._roots = {self.merkle.head().hex(): 0}   # every head this log has genuinely had
        self.require_anchor = require_anchor
        self.require_enrolment = require_enrolment
        self.require_place = require_place
        self.witness_ttl = witness_ttl
        self.store = store if store is not None else MemoryStore()
        self.challenge_ttl = challenge_ttl
        self.sessions = {}     # (tik_pub_hex, session_key) -> {"prev":.., "counter":int}  ephemeral
        self._challenges = {}  # nonce -> expiry                                            ephemeral
        self.log = []

    # ---- the durable ledger -------------------------------------------------------
    _BLANK = {"enrolled_instance": None, "enrolled_place": None,
              "observed_instance": None, "observed_place": None,
              "revoked": False, "reason": None, "contention": [],
              "transfer_authority": None, "transfers": [], "consumed_grants": [],
              "witnessed": []}

    def _rec(self, k):
        r = self.store.get(k)
        return dict(self._BLANK) if r is None else {**self._BLANK, **r}

    def _save(self, k, rec): self.store.put(k, rec)

    @property
    def durable(self): return getattr(self.store, "durable", False)

    @property
    def enrolled(self):
        """identity -> the INSTANCE it is enrolled on (REPORT_ID on SEV-SNP, not CHIP_ID)."""
        out = {}
        for k in self.store.keys():
            a = (self.store.get(k) or {}).get("enrolled_instance")
            if a: out[k] = bytes.fromhex(a)
        return out

    @property
    def identity(self):
        out = {}
        for k in self.store.keys():
            r = self.store.get(k) or {}
            a = r.get("observed_instance"); p = r.get("enrolled_place")
            out[k] = {"anchor": bytes.fromhex(a) if a else None,
                      "place": bytes.fromhex(p) if p else None,
                      "revoked": r.get("revoked", False)}
        return out

    def _witness(self, rec, inst, place):
        """Record an instance whose evidence we actually verified.

        A transfer may only point at one of these. Writing an instance into the ledger that nobody
        has ever proved exists would let a grant name a machine that was never there."""
        now = int(time.time())
        seen = [w for w in rec["witnessed"]
                if w["instance"] != inst.hex() and now - w["at"] < self.witness_ttl]
        rec["witnessed"] = (seen + [{"instance": inst.hex(),
                                     "place": place.hex() if place else None,
                                     "at": now}])[-32:]

    @property
    def contention(self):
        out = {}
        for k in self.store.keys():
            c = (self.store.get(k) or {}).get("contention") or []
            if c: out[k] = c
        return out

    def _emit(self, ev): self.log.append(ev)

    # ---- the transparency side: every decision is a leaf, every leaf gets a receipt ----
    @property
    def public_key(self):
        """SPKI DER. A verifier needs this and nothing else to check a receipt."""
        return self._signing_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def head_for_attestation(self):
        """The head to hand an attester, so its chip witnesses the ledger state we are claiming."""
        return self.merkle.head()

    def knows_head(self, head: bytes):
        """True if this log genuinely had that head. A mandate that cannot account for a head its
        own attester witnessed has been caught holding a second history."""
        return head.hex() in self._roots

    def sth(self):
        """The mandate's signed word about its whole log, right now."""
        return _receipt.sign_sth(self._signing_key, len(self.merkle), self.merkle.head())

    def prove_extension(self, old_size):
        """A consistency proof that the log today extends the log at `old_size`."""
        return [p.hex() for p in self.merkle.prove_consistency(old_size)]

    def receipt(self, index):
        return {"entry": self.merkle.entries[index].hex(),
                "index": index,
                "proof": [p.hex() for p in self.merkle.prove_inclusion(index)],
                "sth": self.sth()}

    def _record(self, kind, tik_pub, accepted, reason, instance=None):
        entry = _receipt.make_entry(kind, tik_pub, accepted, reason, instance,
                                    seq=len(self.merkle))
        index, new_root = self.merkle.append(entry)
        self._roots[new_root.hex()] = len(self.merkle)
        self.last_receipt = self.receipt(index)
        return self.last_receipt

    def _dispute(self, rec, reason):
        """Record a dispute WITH a timestamp: 'within what bound' is not answerable without one.

        Mutates the record the caller is holding rather than doing its own read-modify-write, so a
        later save of that record cannot silently erase the dispute."""
        rec["contention"] = (rec["contention"] + [{"at": int(time.time()), "why": reason}])[-64:]

    # ---- challenge/response: the mandate picks the nonce, and it expires ----
    def challenge(self):
        import os as _os
        n = _os.urandom(32)
        now = time.time()
        self._challenges = {x: e for x, e in self._challenges.items() if e > now}   # drop stale
        self._challenges[n] = now + self.challenge_ttl
        return n

    def _enroll(self, tik_pub, enroll_evidence, nonce, csr_der, transfer_authority=None):
        """One-time: bind an identity key to the instance it was born on.

        Requires (a) a nonce this mandate issued, unspent and unexpired, (b) a CSR that carries
        EXACTLY tik_pub and is self-signed by its private half, (c) a TEE report over
        SHA-512(nonce || CSR) from a platform with a usable anchor. First write wins.

        `transfer_authority` is the SPKI of the key allowed to authorise moving this identity to a
        different instance later -- see hatls.transfer. Omitting it means the identity can never be
        moved, which is the safe default and also means a dead machine ends it."""
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
        if rec["enrolled_instance"] is not None:
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
            self._emit(("enroll-rejected", k[:16], "platform exposes no instance claim"))
            return False, ("platform exposes no usable instance claim: "
                           "continuity-to-an-instance cannot be enrolled here")
        if self.require_place and anchor.get("place") is None:
            self._emit(("enroll-rejected", k[:16], "platform exposes no place claim"))
            return False, "platform exposes no place claim and this mandate requires one"
        del self._challenges[nonce]
        rec["enrolled_instance"] = anchor["instance"].hex()
        rec["enrolled_place"] = anchor["place"].hex() if anchor.get("place") else None
        if transfer_authority is not None:
            rec["transfer_authority"] = transfer_authority.hex()
        self._save(k, rec)
        self._emit(("enrolled", k[:16], anchor["instance"].hex()[:12],
                    "transferable" if transfer_authority is not None else "fixed"))
        return True, "enrolled"

    def enroll(self, tik_pub, enroll_evidence, nonce, csr_der, transfer_authority=None):
        """Bind an identity to its instance, and record the decision. See `_enroll`."""
        ok, why = self._enroll(tik_pub, enroll_evidence, nonce, csr_der, transfer_authority)
        inst = self._rec(tik_pub.hex())["enrolled_instance"] if ok else None
        self._record("enroll", tik_pub, ok, why, bytes.fromhex(inst) if inst else None)
        return ok, why

    def revoke(self, tik_pub, reason="operator"):
        """Explicit, deliberate revocation. Nothing an unauthenticated presenter does reaches here."""
        k = tik_pub.hex()
        rec = self._rec(k); rec["revoked"] = True; rec["reason"] = reason
        self._save(k, rec)
        self._emit(("revoked", k[:16], reason))
        self._record("revoke", tik_pub, True, reason)
        return True, f"identity revoked: {reason}"

    def accept_transfer(self, tik_pub, grant, signature):
        """Move an enrolled identity to another instance, on the authority named at enrolment.

        The mandate does not decide who is right. It checks that the party the identity itself
        nominated has said so, recently, once, about this identity, about the instance it is
        actually on, and about an instance this mandate has itself seen produce valid evidence.

        Two of those deserve saying out loud. A grant that does not name the instance being left
        is a grant to abduct: whoever holds the authority key could lift the identity off a healthy
        machine without ever showing they were entitled to leave it. And a destination the mandate
        has never witnessed is a machine nobody has proved exists -- writing it into the ledger
        would strand the identity on a fiction. Recovery from a dead instance still works, because
        the dead instance's last valid evidence is what `from` names.

        NOTE: a grant is only valid at the mandate that holds this enrolment. Nonces are consumed
        locally, so nothing stops the same grant being presented to a second, independent mandate.
        Making that safe needs a shared log, which is the federation problem and is not solved here.

        Returns (accepted, reason)."""
        k = tik_pub.hex()
        rec = self._rec(k)
        def no(reason, tag):
            self._emit(("transfer-rejected", k[:16], tag))
            self._record("transfer", tik_pub, False, reason)
            return False, reason
        if rec["revoked"]:
            return no("identity revoked", "revoked")
        if rec["enrolled_instance"] is None:
            return no("identity is not enrolled; there is nothing to transfer", "not-enrolled")
        if rec["transfer_authority"] is None:
            return no("identity named no transfer authority at enrolment and cannot be moved",
                      "not-transferable")
        if not isinstance(grant, dict) or grant.get("v") != GRANT_VERSION:
            return no("unsupported grant version", "bad-version")
        if grant.get("tik") != k:
            return no("grant is for a different identity", "wrong-identity")
        try:
            verify_grant(bytes.fromhex(rec["transfer_authority"]), grant, signature)
        except Exception:
            return no("grant is not signed by this identity's transfer authority", "bad-signature")
        now = int(time.time())
        if not (int(grant.get("nbf", 0)) <= now <= int(grant.get("exp", 0))):
            return no("grant is outside its validity window "
                      "(times are the issuer's clock; allow for skew)", "expired")
        if grant.get("nonce") in rec["consumed_grants"]:
            return no("grant has already been used", "replayed")

        # the instance being left must be named, or the operator must have said otherwise in the
        # grant itself -- which is logged separately, because it is a much stronger permission
        any_origin = bool(grant.get("any_origin"))
        if grant.get("from") is None and not any_origin:
            return no("grant does not name the instance being left", "no-origin")
        if grant.get("from") is not None and grant["from"] != rec["enrolled_instance"]:
            return no("grant was issued for a different current instance", "from-mismatch")

        to_hex = grant.get("to")
        if not isinstance(to_hex, str):
            return no("grant carries an unreadable destination", "bad-destination")
        try:
            to_instance = bytes.fromhex(to_hex)
        except Exception:
            return no("grant carries an unreadable destination", "bad-destination")
        if not any(to_instance):
            return no("cannot transfer to a platform with no instance claim", "no-anchor")

        # the destination must be an instance THIS mandate has seen produce valid evidence
        witness = next((w for w in rec["witnessed"]
                        if w["instance"] == to_hex and now - w["at"] < self.witness_ttl), None)
        if witness is None:
            return no("destination instance has not presented valid evidence to this mandate "
                      "(let it attest first, then issue the grant)", "unwitnessed")

        previous = rec["enrolled_instance"]
        rec["enrolled_instance"] = to_hex
        rec["enrolled_place"] = witness.get("place")
        rec["observed_instance"] = None
        rec["observed_place"] = None
        rec["transfers"] = (rec["transfers"] + [{"at": now, "from": previous, "to": to_hex,
                                                 "nonce": grant["nonce"],
                                                 "any_origin": any_origin}])[-64:]
        rec["consumed_grants"] = (rec["consumed_grants"] + [grant["nonce"]])[-256:]
        self._save(k, rec)
        # the instance left behind is no longer authorised, so its live chains end here
        for key in [x for x in self.sessions if x[0] == k]:
            del self.sessions[key]
        if any_origin:
            self._emit(("transfer-any-origin", k[:16], (previous or "")[:12], to_hex[:12]))
        self._emit(("transferred", k[:16], (previous or "")[:12], to_hex[:12]))
        self._record("transfer", tik_pub, True, "transferred to the authorised instance",
                     to_instance)
        return True, "transferred to the authorised instance"

    def _appraise(self, tik_pub, session_context, exporter, msg, head=None):
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
        instance = None
        if rec["revoked"]:
            self._emit(("declined-revoked", k[:16], msg["counter"]))
            return False, "identity revoked", instance

        # 1) the hardware Evidence must be valid AND bind exactly this post_link
        pl = bytes.fromhex(msg["post_link"])
        if head is not None and not self.knows_head(head):
            self._emit(("declined-unknown-head", k[:16], head.hex()[:12]))
            return False, "the ledger head offered for this attestation is not one this log had", instance
        ok, anchor = self.verify_report(msg["evidence"], report_data_for(pl, head))
        if not ok:
            self._emit(("declined-evidence", k[:16], msg["counter"]))
            return False, "evidence invalid or does not bind the link", instance

        # 1a) FAIL CLOSED on a platform that cannot name its own instance. An all-zero anchor is
        #     not an identity: on such a platform every machine looks alike, so accepting it would
        #     silently hand out a guarantee we cannot keep.
        if anchor is None:
            if self.require_anchor:
                self._emit(("declined-no-anchor", k[:16], msg["counter"]))
                return False, ("platform exposes no usable instance claim: re-hosting is "
                               "undecidable here (set require_anchor=False to accept that)"), instance
            self._emit(("anchor-absent-downgraded", k[:16], msg["counter"]))

        enrolled_instance = (bytes.fromhex(rec["enrolled_instance"])
                             if rec["enrolled_instance"] else None)
        instance = anchor["instance"] if anchor else None
        place = anchor.get("place") if anchor else None

        # 1b) NO SILENT DOWNGRADE. An empty ledger and a deliberately unenrolled identity look the
        #     same from here, so a deployment that relies on the enrolment gate must say so: a lost
        #     or wiped ledger then refuses service instead of quietly reverting to the weaker mode.
        if enrolled_instance is None and self.require_enrolment:
            self._emit(("declined-not-enrolled", k[:16], msg["counter"]))
            return False, ("identity has no enrolment on record and this mandate requires one "
                           "(a lost ledger must not silently downgrade the guarantee)"), instance

        # 1c) ENROLMENT GATE. Evidence from any instance other than the enrolled one is an
        #     impostor, rejected on its FIRST message. We know which instance is legitimate, so we
        #     reject the PRESENTER and leave the victim's identity untouched. The evidence was
        #     valid, though, so we record having seen that instance: a later transfer may only
        #     point at an instance this mandate has actually witnessed.
        if enrolled_instance is not None and instance is not None and instance != enrolled_instance:
            self._witness(rec, instance, place)
            self._dispute(rec, "evidence from a non-enrolled instance")
            self._save(k, rec)
            self._emit(("rejected-impostor", k[:16], enrolled_instance.hex()[:12],
                        instance.hex()[:12], msg["counter"]))
            return False, "rejected: key presented from an instance it was not enrolled on", instance

        # 1d) a deployment may additionally pin the silicon. This is a separate, weaker claim than
        #     identity: two guests on one socket share a place, and a shared-tenancy platform has
        #     none at all.
        if self.require_place and place is None:
            self._emit(("declined-no-place", k[:16], msg["counter"]))
            return False, "platform exposes no place claim and this mandate requires one", instance
        enrolled_place = bytes.fromhex(rec["enrolled_place"]) if rec["enrolled_place"] else None
        if self.require_place and enrolled_place is not None and place != enrolled_place:
            self._dispute(rec, "instance moved to different silicon")
            self._save(k, rec)
            self._emit(("declined-place-changed", k[:16], msg["counter"]))
            return False, "the enrolled instance is reporting from different silicon", instance

        # 2) Without enrolment we cannot tell owner from thief, so we protect the incumbent and
        #    record a dispute. We do NOT destroy the identity on an unauthenticated claim.
        observed = (bytes.fromhex(rec["observed_instance"])
                    if rec["observed_instance"] else None)
        if observed is not None and instance is not None and instance != observed:
            self._witness(rec, instance, place)
            self._dispute(rec, "second instance under one identity")
            self._save(k, rec)
            self._emit(("contention-anchor", k[:16], observed.hex()[:12],
                        instance.hex()[:12], msg["counter"]))
            return False, ("continuity contention: a second instance claims this identity "
                           "(no enrolment on record, so the mandate refuses to pick a winner)"), instance

        # 3) the chain of THIS connection. A session we have not seen must start at counter 0; one
        #    we have seen must advance by exactly one.
        sess = self.sessions.get((k, skey))
        if sess is None:
            if msg["counter"] != 0:
                self._emit(("declined-counter", k[:16], "new session", msg["counter"]))
                return False, "a session's first link must be counter 0", instance
            base = intra_link(session_context, tik_pub)
        else:
            if msg["counter"] != sess["counter"] + 1:
                self._dispute(rec, "counter did not advance"); self._save(k, rec)
                self._emit(("declined-counter", k[:16], sess["counter"], msg["counter"]))
                return False, "counter did not advance by one (replay or reorder)", instance
            base = sess["prev"]

        # 4) recompute the link ourselves from values we derived, not values we were handed
        if post_link(exporter, base, msg["counter"]) != pl:
            self._dispute(rec, "link does not chain"); self._save(k, rec)
            self._emit(("declined-linkmismatch", k[:16], msg["counter"]))
            return False, "link does not chain (relay, replay or a foreign session)", instance

        self.sessions[(k, skey)] = {"prev": pl, "counter": msg["counter"]}
        if instance is not None:
            rec["observed_instance"] = instance.hex()
            rec["observed_place"] = place.hex() if place else None
            self._save(k, rec)
        self._emit(("accept", k[:16], skey[:8], msg["counter"],
                    instance.hex()[:12] if instance else "no-instance"))
        return True, "accepted; continuity intact", instance

    def present(self, tik_pub, session_context, exporter, msg, head=None):
        """Appraise one step and record the decision in the log. Returns (accepted, reason);
        the receipt for this decision is `self.last_receipt`.

        `head` is the ledger head this relying party gave the attester before it signed. When one
        is used, the hardware report commits to it, and the report becomes evidence of what this
        mandate claimed its log was at that moment."""
        ok, why, instance = self._appraise(tik_pub, session_context, exporter, msg, head)
        self._record("present", tik_pub, ok, why, instance)
        return ok, why
