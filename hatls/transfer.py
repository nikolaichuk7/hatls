#!/usr/bin/env python3
"""Authorised transfer: how a disputed identity is resolved, and how a legitimate one moves.

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

def make_grant(authority_key, tik_pub, to_anchor, valid_for=900, from_anchor=None, now=None):
    """Issue a single-use, time-bounded permission to move `tik_pub` onto `to_anchor`.

    `from_anchor` pins the grant to the instance the identity is on now, so a grant issued for one
    situation cannot be kept and replayed against a later one. Leaving it None permits the move
    from wherever the identity currently is."""
    now = int(time.time() if now is None else now)
    grant = {"v": GRANT_VERSION,
             "tik": tik_pub.hex(),
             "to": to_anchor.hex(),
             "from": from_anchor.hex() if from_anchor else None,
             "nbf": now,
             "exp": now + int(valid_for),
             "nonce": os.urandom(16).hex()}
    signature = authority_key.sign(canonical(grant), ec.ECDSA(hashes.SHA256()))
    return grant, signature

def verify_grant(authority_spki_der, grant, signature):
    """True if `signature` is this authority's over exactly these grant fields."""
    pub = serialization.load_der_public_key(authority_spki_der)
    pub.verify(signature, canonical(grant), ec.ECDSA(hashes.SHA256()))
    return True
