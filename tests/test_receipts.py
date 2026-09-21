"""Receipts: what stops the mandate denying what it said, and what catches it saying two things.

These tests attack the mandate itself, which every other test file assumes is honest.
"""
import os, sys, hashlib, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr
from hatls.tee import MockTEE, mock_verifier
from hatls.log import MerkleLog, root
from hatls import receipt as R

CHIP_A = (b"\xa2\xb2\x58\x0a" * 16)[:64]
CHIP_B = (b"\x76\x10\x22\xd0" * 16)[:64]

def _key():
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)

KEY, TIK = _key(); CSR = make_enrolment_csr(KEY)

def _mandate(**kw):
    tA, tB = MockTEE(CHIP_A), MockTEE(CHIP_B)
    m = Mandate(mock_verifier({tA.pub.hex(), tB.pub.hex()}), **kw)
    n = m.challenge()
    assert m.enroll(TIK, tA.report(hashlib.sha512(n + CSR).digest()), n, CSR)[0]
    return m, tA, tB

def _present(m, tee):
    c, e = os.urandom(48), os.urandom(32)
    return m.present(TIK, c, e, Attester(tee, TIK).attest(c, e))

# ---------------- every decision leaves a receipt ----------------
def test_an_accepted_decision_yields_a_verifiable_receipt():
    m, tA, _ = _mandate()
    assert _present(m, tA)[0]
    ok, why = R.verify_receipt(m.public_key, m.last_receipt)
    assert ok, why

def test_a_REFUSED_decision_yields_one_too():
    """The refusals are the interesting ones: they are what a wronged party needs to show."""
    m, _, tB = _mandate()
    assert not _present(m, tB)[0]
    ok, why = R.verify_receipt(m.public_key, m.last_receipt)
    assert ok, why
    import json
    entry = json.loads(bytes.fromhex(m.last_receipt["entry"]))
    assert entry["accepted"] is False and "not enrolled" in entry["reason"]

def test_enrolment_and_revocation_are_logged_too():
    m, tA, _ = _mandate()
    m.revoke(TIK, reason="incident 42")
    assert R.verify_receipt(m.public_key, m.last_receipt)[0]
    import json
    kinds = [json.loads(e)["kind"] for e in m.merkle.entries]
    assert kinds[0] == "enroll" and kinds[-1] == "revoke"

def test_the_log_does_not_store_the_identity_key_itself():
    m, tA, _ = _mandate(); _present(m, tA)
    joined = b"".join(m.merkle.entries)
    assert TIK.hex().encode() not in joined
    assert R.identity_tag(TIK).encode() in joined

# ---------------- forgery and substitution ----------------
def test_a_tampered_entry_is_rejected():
    m, tA, _ = _mandate(); _present(m, tA)
    r = dict(m.last_receipt); r["entry"] = R.make_entry("present", TIK, True, "forged").hex()
    ok, why = R.verify_receipt(m.public_key, r)
    assert not ok and "not in the log" in why

def test_a_receipt_from_another_mandate_is_rejected():
    m1, tA, _ = _mandate(); _present(m1, tA)
    m2, _, _ = _mandate()
    ok, why = R.verify_receipt(m2.public_key, m1.last_receipt)
    assert not ok and "not signed by this mandate" in why

def test_a_head_with_a_swapped_root_is_rejected():
    m, tA, _ = _mandate(); _present(m, tA)
    r = dict(m.last_receipt); r["sth"] = dict(r["sth"]); r["sth"]["root"] = os.urandom(32).hex()
    ok, why = R.verify_receipt(m.public_key, r)
    assert not ok and "not signed by this mandate" in why

# ---------------- the log cannot be rewritten ----------------
def test_the_log_only_ever_extends():
    m, tA, _ = _mandate()
    old = m.sth()
    for _ in range(5): _present(m, tA)
    new = m.sth()
    assert R.verify_extension(m.public_key, old, new, m.prove_extension(old["size"]))

def test_a_dropped_decision_breaks_the_extension_proof():
    m, tA, _ = _mandate()
    for _ in range(4): _present(m, tA)
    old = m.sth()
    m.merkle.entries.pop(2)                       # the mandate edits its history
    for _ in range(2): _present(m, tA)
    new = m.sth()
    try:
        ok = R.verify_extension(m.public_key, old, new, m.prove_extension(old["size"]))
    except Exception:
        ok = False
    assert not ok, "a rewritten log must not prove it extends the old one"

# ---------------- equivocation ----------------
def test_two_heads_that_neither_extends_are_caught():
    """A mandate telling two relying parties different histories. It cannot be prevented by a
    single component; it can be proved, and both its own signatures are the proof."""
    m, tA, tB = _mandate()
    for _ in range(3): _present(m, tA)
    branch_a = m.sth()
    saved = list(m.merkle.entries)
    m.merkle.entries = saved[:2] + [R.make_entry("present", TIK, True, "a different history")]
    branch_b = m.sth()
    caught, why = R.is_equivocation(m.public_key, branch_a, branch_b)
    assert caught and "equivocation" in why

def test_an_honest_pair_of_heads_is_not_called_equivocation():
    m, tA, _ = _mandate()
    old = m.sth()
    for _ in range(3): _present(m, tA)
    new = m.sth()
    caught, why = R.is_equivocation(m.public_key, old, new,
                                    proof_a_to_b=m.prove_extension(old["size"]))
    assert not caught and "extends" in why

def test_the_same_head_twice_is_not_equivocation():
    m, tA, _ = _mandate(); _present(m, tA)
    a = m.sth(); b = m.sth()
    caught, _ = R.is_equivocation(m.public_key, a, b)
    assert not caught

# ---------------- honesty about the signing key ----------------
def test_an_ephemeral_signing_key_is_flagged():
    m, _, _ = _mandate()
    assert m.ephemeral_signing_key is True, "a mandate that invented its key must say so"

def test_a_supplied_key_survives_a_restart_so_old_receipts_still_verify():
    key, pub = _key()
    m, tA, _ = _mandate(signing_key=key)
    _present(m, tA)
    kept = m.last_receipt
    m2, _, _ = _mandate(signing_key=key)          # the process comes back with the same key
    assert not m2.ephemeral_signing_key
    assert R.verify_receipt(m2.public_key, kept)[0], "receipts outlive the process that issued them"
