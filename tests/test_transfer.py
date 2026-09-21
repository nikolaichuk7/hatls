"""Authorised transfer: the mandate enforces someone else's decision, and nothing else.

Grants name **instances** (REPORT_ID), not silicon. A grant must be useless to everyone except the
party the identity nominated, and useless to that party more than once, outside its window, about
another identity, from an instance the identity is not on, or onto an instance nobody has seen.
"""
import os, sys, time, hashlib, tempfile, shutil, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr
from hatls.transfer import make_grant, authority_public_bytes
from hatls.store import FileStore
from hatls.tee import MockTEE, mock_verifier

CHIP_A = (b"\xa2\xb2\x58\x0a" * 16)[:64]
CHIP_B = (b"\x76\x10\x22\xd0" * 16)[:64]

def _key():
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)

KEY, TIK = _key(); CSR = make_enrolment_csr(KEY)
OWNER, OWNER_PUB = _key()
ROGUE, ROGUE_PUB = _key()

def _world(**kw):
    tA, tB, tC = MockTEE(CHIP_A), MockTEE(CHIP_B), MockTEE(CHIP_A)
    v = mock_verifier({tA.pub.hex(), tB.pub.hex(), tC.pub.hex()})
    return Mandate(v, **kw), tA, tB, tC

@pytest.fixture
def world(): return _world()

def _enrol(m, tee, authority=OWNER_PUB):
    n = m.challenge()
    ok, why = m.enroll(TIK, tee.report(hashlib.sha512(n + CSR).digest()), n, CSR,
                       transfer_authority=authority)
    assert ok, why

def _present(m, tee):
    c, e = os.urandom(48), os.urandom(32)
    return m.present(TIK, c, e, Attester(tee, TIK).attest(c, e))

def _witness(m, tee):
    """Let an instance prove it exists. It is refused, but its evidence was verified."""
    ok, _ = _present(m, tee)
    assert not ok
    return tee.instance

# ---------------- the happy path, in the order the mandate requires ----------------
def test_an_authorised_transfer_moves_the_identity(world):
    m, tA, tB, _ = world
    _enrol(m, tA)
    assert _present(m, tA)[0]
    _witness(m, tB)                                     # B attests first and is refused
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert ok, why
    assert _present(m, tB)[0], "after the grant, B is the identity"
    ok2, why2 = _present(m, tA)
    assert not ok2 and "not enrolled" in why2, "the instance it left must lose the identity"

def test_recovery_after_the_enrolled_instance_dies(world):
    """A never comes back. Its last enrolment is exactly what `from` names."""
    m, tA, tB, _ = world
    _enrol(m, tA); assert _present(m, tA)[0]
    _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    assert m.accept_transfer(TIK, grant, sig)[0]
    assert _present(m, tB)[0]

def test_transfer_ends_the_old_instances_live_sessions(world):
    m, tA, tB, _ = world
    _enrol(m, tA)
    c, e = os.urandom(48), os.urandom(32); a = Attester(tA, TIK)
    assert m.present(TIK, c, e, a.attest(c, e))[0]
    _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    assert m.accept_transfer(TIK, grant, sig)[0]
    assert not m.present(TIK, c, e, a.attest(c, e))[0]

def test_a_transfer_survives_a_restart():
    d = tempfile.mkdtemp(prefix="hatls-xfer-")
    try:
        tA, tB = MockTEE(CHIP_A), MockTEE(CHIP_B)
        v = mock_verifier({tA.pub.hex(), tB.pub.hex()})
        m = Mandate(v, store=FileStore(d)); _enrol(m, tA); _witness(m, tB)
        grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
        assert m.accept_transfer(TIK, grant, sig)[0]
        restarted = Mandate(v, store=FileStore(d))
        assert _present(restarted, tB)[0]
        assert not _present(restarted, tA)[0]
    finally:
        shutil.rmtree(d, ignore_errors=True)

# ---------------- the two holes the review found ----------------
def test_a_grant_must_name_the_instance_being_left():
    """Without it, whoever holds the authority key can lift the identity off a healthy machine."""
    with pytest.raises(ValueError):
        make_grant(OWNER, TIK, MockTEE(CHIP_B).instance)

def test_any_origin_is_possible_but_deliberate_and_logged(world):
    m, tA, tB, _ = world
    _enrol(m, tA); _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, any_origin=True)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert ok, why
    assert any(ev[0] == "transfer-any-origin" for ev in m.log)
    assert m._rec(TIK.hex())["transfers"][-1]["any_origin"] is True

def test_a_destination_nobody_has_seen_is_refused(world):
    """The mandate must not write an instance into the ledger that never proved it exists."""
    m, tA, tB, _ = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "has not presented valid evidence" in why

def test_a_witness_goes_stale(world):
    m, tA, tB, _ = _world(witness_ttl=0)
    _enrol(m, tA); _witness(m, tB)
    time.sleep(0.01)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "has not presented valid evidence" in why

# ---------------- everything else that must fail ----------------
def test_an_identity_that_named_no_authority_cannot_be_moved(world):
    m, tA, tB, _ = world
    _enrol(m, tA, authority=None); _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "cannot be moved" in why

def test_a_grant_is_single_use(world):
    m, tA, tB, tC = world
    _enrol(m, tA); _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    assert m.accept_transfer(TIK, grant, sig)[0]
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "already been used" in why

def test_an_expired_grant_is_refused(world):
    m, tA, tB, _ = world
    _enrol(m, tA); _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance, valid_for=-1)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "validity window" in why

def test_a_grant_not_yet_valid_is_refused(world):
    m, tA, tB, _ = world
    _enrol(m, tA); _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance,
                            now=time.time() + 600)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "validity window" in why

def test_a_grant_from_the_wrong_key_is_refused(world):
    m, tA, tB, _ = world
    _enrol(m, tA); _witness(m, tB)
    grant, sig = make_grant(ROGUE, TIK, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "transfer authority" in why

def test_a_grant_for_another_identity_is_refused(world):
    m, tA, tB, _ = world
    _enrol(m, tA); _witness(m, tB)
    _, other = _key()
    grant, sig = make_grant(OWNER, other, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "different identity" in why

def test_a_tampered_grant_is_refused(world):
    m, tA, tB, tC = world
    _enrol(m, tA); _witness(m, tB); _witness(m, tC)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    grant["to"] = tC.instance.hex()
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "transfer authority" in why

def test_a_grant_pinned_to_a_different_current_instance_is_refused(world):
    m, tA, tB, tC = world
    _enrol(m, tA); _witness(m, tB)
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tC.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "different current instance" in why

def test_a_revoked_identity_cannot_be_transferred(world):
    m, tA, tB, _ = world
    _enrol(m, tA); _witness(m, tB); m.revoke(TIK, reason="key disclosed")
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "revoked" in why

def test_cannot_transfer_onto_a_platform_with_no_instance_claim(world):
    m, tA, tB, _ = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, bytes(32), from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "no instance claim" in why

def test_an_unenrolled_identity_cannot_be_transferred(world):
    m, tA, tB, _ = world
    grant, sig = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "not enrolled" in why

# ---------------- the dispute record ----------------
def test_contention_entries_carry_a_timestamp(world):
    m, tA, tB, _ = world
    _enrol(m, tA); _present(m, tB)
    entries = m.contention[TIK.hex()]
    assert entries and all("at" in x and "why" in x for x in entries)
    assert abs(entries[-1]["at"] - int(time.time())) < 60

def test_the_transfer_history_is_recorded(world):
    m, tA, tB, tC = world
    _enrol(m, tA); _witness(m, tB)
    g1, s1 = make_grant(OWNER, TIK, tB.instance, from_instance=tA.instance)
    assert m.accept_transfer(TIK, g1, s1)[0]
    _witness(m, tC)
    g2, s2 = make_grant(OWNER, TIK, tC.instance, from_instance=tB.instance)
    assert m.accept_transfer(TIK, g2, s2)[0]
    hist = m._rec(TIK.hex())["transfers"]
    assert [h["to"] for h in hist] == [tB.instance.hex(), tC.instance.hex()]
    assert hist[0]["from"] == tA.instance.hex() and hist[1]["from"] == tB.instance.hex()
