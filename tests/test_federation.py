"""Two mandates over one identity, with the attester as the channel between them.

Preventing divergence needs consensus. Detecting it needs only that the two claims meet somewhere,
and here they meet inside a hardware report that neither mandate can forge.
"""
import os, sys, hashlib, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr, report_data_for
from hatls.tee import MockTEE, mock_verifier
from hatls import federation as F, receipt as R

CHIP = (b"\xa2\xb2\x58\x0a" * 16)[:64]

def _key():
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
KEY, TIK = _key(); CSR = make_enrolment_csr(KEY)

@pytest.fixture
def pair():
    """Two independent mandates and one guest enrolled with both."""
    tee = MockTEE(CHIP); v = mock_verifier({tee.pub.hex()})
    a, b = Mandate(v), Mandate(v)
    for m in (a, b):
        n = m.challenge()
        assert m.enroll(TIK, tee.report(hashlib.sha512(n + CSR).digest()), n, CSR)[0]
    return a, b, tee

def _attest_to_both(a, b, tee):
    """One attestation carrying both mandates' heads. Neither mandate trusts the other."""
    commitment, entries = F.make_bundle([(a.public_key, a.sth()), (b.public_key, b.sth())])
    c, e = os.urandom(48), os.urandom(32)
    msg = Attester(tee, TIK).attest(c, e, head=commitment)
    return commitment, entries, c, e, msg

# ---------------- the bundle works for both, independently ----------------
def test_one_attestation_satisfies_two_independent_mandates(pair):
    a, b, tee = pair
    commitment, entries, c, e, msg = _attest_to_both(a, b, tee)
    oka, whya = a.present(TIK, c, e, msg, head=commitment, bundle=entries)
    okb, whyb = b.present(TIK, c, e, msg, head=commitment, bundle=entries)
    assert oka, whya
    assert okb, whyb

def test_the_bundle_names_both_mandates(pair):
    a, b, tee = pair
    _, entries, *_ = _attest_to_both(a, b, tee)
    assert {e["m"] for e in entries} == {a.id, b.id}
    assert F.entry_for(entries, a.public_key)["root"] == a.sth()["root"]

def test_a_tampered_bundle_is_refused(pair):
    a, b, tee = pair
    commitment, entries, c, e, msg = _attest_to_both(a, b, tee)
    forged = [dict(x) for x in entries]; forged[0]["root"] = os.urandom(32).hex()
    ok, why = a.present(TIK, c, e, msg, head=commitment, bundle=forged)
    assert not ok and "does not match what was bound" in why

def test_a_mandate_absent_from_the_bundle_refuses(pair):
    a, b, tee = pair
    c_, other = Mandate(mock_verifier({tee.pub.hex()})), None
    commitment, entries = F.make_bundle([(a.public_key, a.sth()), (b.public_key, b.sth())])
    c, e = os.urandom(48), os.urandom(32)
    msg = Attester(tee, TIK).attest(c, e, head=commitment)
    ok, why = c_.present(TIK, c, e, msg, head=commitment, bundle=entries)
    assert not ok and "not named in the bundle" in why

def test_a_bundle_naming_a_head_the_log_never_had_is_refused(pair):
    a, b, tee = pair
    fake = dict(a.sth()); fake["root"] = os.urandom(32).hex()
    entries = F.bundle_entries([(a.public_key, fake), (b.public_key, b.sth())])
    commitment = F.bundle_commitment(entries)
    c, e = os.urandom(48), os.urandom(32)
    msg = Attester(tee, TIK).attest(c, e, head=commitment)
    ok, why = a.present(TIK, c, e, msg, head=commitment, bundle=entries)
    assert not ok and "never had" in why

def test_a_bundle_of_unsigned_claims_is_refused_at_construction(pair):
    a, b, tee = pair
    forged = dict(a.sth()); forged["root"] = os.urandom(32).hex()
    with pytest.raises(Exception):
        F.make_bundle([(a.public_key, forged)])

# ---------------- the point: divergence becomes evidence ----------------
def test_a_mandate_that_rewrites_after_being_witnessed_is_caught(pair):
    """A and B both served this attestation. A then adopts a history its witnessed head does not
    extend. The AMD-signed report plus A's own later head are the whole proof -- B never had to
    trust A, and no consensus ran."""
    a, b, tee = pair
    commitment, entries, c, e, msg = _attest_to_both(a, b, tee)
    assert a.present(TIK, c, e, msg, head=commitment, bundle=entries)[0]
    assert b.present(TIK, c, e, msg, head=commitment, bundle=entries)[0]

    witnessed = F.entry_for(entries, a.public_key)          # carried inside the hardware report
    a.merkle.entries = [R.make_entry("present", TIK, True, "a different history", seq=0)]
    a._roots = {a.merkle.head().hex(): 1}

    try:
        proof = a.prove_extension(witnessed["size"])
    except Exception:
        proof = None
    diverged, why = F.divergence(a.public_key, witnessed["size"], witnessed["root"], a.sth(), proof)
    assert diverged, why
    assert F.verify_bundle(commitment, entries), "the evidence itself still stands up"

def test_an_honest_peer_shows_it_extended_what_was_witnessed(pair):
    a, b, tee = pair
    commitment, entries, c, e, msg = _attest_to_both(a, b, tee)
    assert a.present(TIK, c, e, msg, head=commitment, bundle=entries)[0]
    witnessed = F.entry_for(entries, a.public_key)
    for _ in range(3):
        cc, ee = os.urandom(48), os.urandom(32)
        a.present(TIK, cc, ee, Attester(tee, TIK).attest(cc, ee))
    diverged, why = F.divergence(a.public_key, witnessed["size"], witnessed["root"],
                                 a.sth(), a.prove_extension(witnessed["size"]))
    assert not diverged and "extends" in why

def test_a_shrunken_log_is_divergence_on_its_face(pair):
    a, b, tee = pair
    for _ in range(4):
        cc, ee = os.urandom(48), os.urandom(32)
        a.present(TIK, cc, ee, Attester(tee, TIK).attest(cc, ee))
    big = a.sth()
    a.merkle.entries = a.merkle.entries[:2]
    diverged, why = F.divergence(a.public_key, big["size"], big["root"], a.sth(), None)
    assert diverged and "shrunk" in why

def test_two_roots_at_one_size_is_divergence(pair):
    a, b, tee = pair
    cc, ee = os.urandom(48), os.urandom(32)
    a.present(TIK, cc, ee, Attester(tee, TIK).attest(cc, ee))
    now = a.sth()
    diverged, why = F.divergence(a.public_key, now["size"], os.urandom(32).hex(), now, None)
    assert diverged and "two histories" in why

def test_refusing_to_prove_is_itself_the_answer(pair):
    a, b, tee = pair
    witnessed = a.sth()
    for _ in range(2):
        cc, ee = os.urandom(48), os.urandom(32)
        a.present(TIK, cc, ee, Attester(tee, TIK).attest(cc, ee))
    diverged, why = F.divergence(a.public_key, witnessed["size"], witnessed["root"], a.sth(), None)
    assert diverged and "no proof" in why

# ---------------- direct cross-witnessing, when the mandates can talk ----------------
def test_a_mandate_can_sign_what_it_saw_of_another(pair):
    a, b, tee = pair
    stmt = a.observe(b.public_key, b.sth())
    assert F.verify_cross_witness(a.public_key, stmt)
    assert stmt["peer"] == b.id

def test_a_forged_cross_witness_is_rejected(pair):
    a, b, tee = pair
    stmt = a.observe(b.public_key, b.sth())
    stmt = dict(stmt); stmt["root"] = os.urandom(32).hex()
    with pytest.raises(Exception):
        F.verify_cross_witness(a.public_key, stmt)

def test_mandate_ids_are_stable_and_distinct(pair):
    a, b, _ = pair
    assert a.id != b.id and a.id == F.mandate_id(a.public_key) and len(a.id) == 32
