#!/usr/bin/env python3
"""Authority-signed permissions: who may create an identity here, and who may move one.

Recording contention was the right primitive and the wrong stopping point. A mandate that sees two
instances claiming one identity cannot settle the question by looking harder at either of them:
both present genuine hardware evidence, and the difference between a thief and an operator
recovering from a dead machine is not visible in any attestation report. Adjudication by heuristic
-- first writer wins, majority, hold-down timers -- only moves the unfairness around.

So the mandate does not adjudicate. It enforces a decision taken elsewhere.

At enrolment an identity may name a **transfer authority**: a public key held by whoever owns the
workload, not by the platform and not by the mandate. That authority can then issue a grant, a
signed statement that this identity may live on that instance, valid between two times and usable
once. The mandate checks the signature, the window and the nonce, and moves the enrolment. An
identity that names no authority cannot be moved at all, which is the safe default.

This also fixes a failure the enrolment gate created. Once an identity is bound to an instance, a
machine that dies takes the identity with it: the operator relaunches, the new instance is refused,
and nothing short of manual surgery helps. Recovery and re-hosting look identical from the mandate's
side, because they *are* identical -- the only difference is whether the owner meant it. A grant is
exactly the owner saying so.
"""
import json, os, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

GRANT_VERSION = 1

def canonical(grant):
    """The exact bytes that are signed. Deterministic, so a verifier rebuilds them identically."""
    return json.dumps(grant, sort_keys=True, separators=(",", ":")).encode()

def authority_public_bytes(authority_key):
    pub = authority_key.public_key() if hasattr(authority_key, "public_key") else authority_key
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)

def make_grant(authority_key, tik_pub, to_instance, from_instance=None, valid_for=900,
               any_origin=False, now=None):
    """Issue a single-use, time-bounded permission to move `tik_pub` onto `to_instance`.

    Both values are **instance** claims -- REPORT_ID on SEV-SNP, the thing that answers "is this
    the same Target Environment". They are not CHIP_ID: two guests on one socket share a chip, and
    a shared-tenancy platform has none, so a grant written in silicon would move the wrong thing or
    nothing at all.

    `from_instance` is required. A grant that does not say which instance is being left is a grant
    to abduct: anyone holding the authority key could lift the identity off a healthy machine
    without showing they were entitled to leave it. Recovery from a dead machine still works --
    the dead instance's last enrolment is exactly what `from_instance` names.

    `any_origin=True` deliberately drops that requirement. It is a far stronger permission, it is
    recorded in the grant so the mandate can see the intent rather than infer it, and the mandate
    logs a separate audit event when one is used.

    `nbf`/`exp` are seconds on the ISSUER's clock. Nothing here reconciles clocks between issuer
    and mandate, so the window is an operational bound, not a cryptographic one; a deployment
    should choose `valid_for` with its own skew budget in mind."""
    if from_instance is None and not any_origin:
        raise ValueError("from_instance is required; pass any_origin=True to issue the stronger "
                         "permission deliberately")
    now = int(time.time() if now is None else now)
    grant = {"v": GRANT_VERSION,
             "tik": tik_pub.hex(),
             "to": to_instance.hex(),
             "from": from_instance.hex() if from_instance else None,
             "any_origin": bool(any_origin),
             "nbf": now,
             "exp": now + int(valid_for),
             "nonce": os.urandom(16).hex()}
    signature = authority_key.sign(canonical(grant), ec.ECDSA(hashes.SHA256()))
    return grant, signature

def verify_grant(authority_spki_der, grant, signature):
    """True if `signature` is this authority's over exactly these grant fields.

    The signed bytes are canonical JSON, which is adequate here and is NOT an interoperable
    encoding: a second implementation in another language will not agree on it by accident. A real
    specification would use COSE."""
    pub = serialization.load_der_public_key(authority_spki_der)
    pub.verify(signature, canonical(grant), ec.ECDSA(hashes.SHA256()))
    return True


# ---- enrolment authorisation: who is allowed to create an identity on this mandate ----
def make_enrolment_authorisation(authority_key, tik_pub, nonce, valid_for=900, now=None):
    """Permission for ONE enrolment of ONE identity against ONE challenge.

    First-write-wins closes re-enrolment but not the race to be first: on a mandate that will
    enrol anybody, an attacker who reaches it before the rightful owner simply owns the identity,
    and every later guarantee is then working perfectly on behalf of the wrong party. A mandate
    configured with an enrolment authority refuses enrolments that this key has not permitted.

    The permission is bound to the mandate's own challenge nonce, so it cannot be collected and
    replayed against a later enrolment attempt."""
    now = int(time.time() if now is None else now)
    body = {"v": GRANT_VERSION, "kind": "enrol",
            "tik": tik_pub.hex(), "nonce": nonce.hex(),
            "nbf": now, "exp": now + int(valid_for)}
    signature = authority_key.sign(canonical(body), ec.ECDSA(hashes.SHA256()))
    return body, signature

def verify_enrolment_authorisation(authority_spki_der, body, signature, tik_pub, nonce):
    """Returns (ok, reason)."""
    if not isinstance(body, dict) or body.get("v") != GRANT_VERSION or body.get("kind") != "enrol":
        return False, "unsupported enrolment authorisation"
    if body.get("tik") != tik_pub.hex():
        return False, "enrolment authorisation is for a different identity"
    if body.get("nonce") != nonce.hex():
        return False, "enrolment authorisation is for a different challenge"
    now = int(time.time())
    if not (int(body.get("nbf", 0)) <= now <= int(body.get("exp", 0))):
        return False, ("enrolment authorisation is outside its validity window "
                       "(times are the issuer's clock; allow for skew)")
    try:
        pub = serialization.load_der_public_key(authority_spki_der)
        pub.verify(signature, canonical(body), ec.ECDSA(hashes.SHA256()))
    except Exception:
        return False, "enrolment authorisation is not signed by this mandate's enrolment authority"
    return True, "authorised"
