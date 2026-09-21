"""Authorised transfer: the mandate enforces someone else's decision, and nothing else.

A grant must be useless to everyone except the party the identity nominated, and useless to that
party more than once, outside its window, or about anything but the situation it was issued for.
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
CHIP_C = (b"\x31\x41\x59\x26" * 16)[:64]

def _key():
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)

KEY, TIK = _key(); CSR = make_enrolment_csr(KEY)
OWNER, OWNER_PUB = _key()          # the workload owner: holds the transfer authority
ROGUE, ROGUE_PUB = _key()          # someone else entirely

@pytest.fixture
def world():
    tA, tB, tC = MockTEE(CHIP_A), MockTEE(CHIP_B), MockTEE(CHIP_C)
    m = Mandate(mock_verifier({tA.pub.hex(), tB.pub.hex(), tC.pub.hex()}))
    return m, tA, tB, tC

def _enrol(m, tee, authority=OWNER_PUB):
    n = m.challenge()
    ok, why = m.enroll(TIK, tee.report(hashlib.sha512(n + CSR).digest()), n, CSR,
                       transfer_authority=authority)
    assert ok, why

def _present(m, tee):
    c, e = os.urandom(48), os.urandom(32)
    return m.present(TIK, c, e, Attester(tee, TIK).attest(c, e))

# ---------------- the happy path ----------------
def test_an_authorised_transfer_moves_the_identity(world):
    m, tA, tB, _ = world
    _enrol(m, tA)
    assert _present(m, tA)[0]
    assert not _present(m, tB)[0], "before the grant, B is an impostor"
    grant, sig = make_grant(OWNER, TIK, CHIP_B, from_anchor=CHIP_A)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert ok, why
    assert _present(m, tB)[0], "after the grant, B is the identity"
    ok2, why2 = _present(m, tA)
    assert not ok2 and "not enrolled" in why2, "the machine it left must lose the identity"

def test_transfer_ends_the_old_instances_live_sessions(world):
    m, tA, tB, _ = world
    _enrol(m, tA)
    c, e = os.urandom(48), os.urandom(32); a = Attester(tA, TIK)
    assert m.present(TIK, c, e, a.attest(c, e))[0]
    grant, sig = make_grant(OWNER, TIK, CHIP_B)
    assert m.accept_transfer(TIK, grant, sig)[0]
    ok, why = m.present(TIK, c, e, a.attest(c, e))
    assert not ok, "a chain from the instance that was left behind must not continue"

def test_a_transfer_survives_a_restart():
    d = tempfile.mkdtemp(prefix="hatls-xfer-")
    try:
        tA, tB = MockTEE(CHIP_A), MockTEE(CHIP_B)
        v = mock_verifier({tA.pub.hex(), tB.pub.hex()})
        m = Mandate(v, store=FileStore(d)); _enrol(m, tA)
        grant, sig = make_grant(OWNER, TIK, CHIP_B)
        assert m.accept_transfer(TIK, grant, sig)[0]
        restarted = Mandate(v, store=FileStore(d))
        assert _present(restarted, tB)[0]
        assert not _present(restarted, tA)[0]
    finally:
        shutil.rmtree(d, ignore_errors=True)

# ---------------- everything that must fail ----------------
def test_an_identity_that_named_no_authority_cannot_be_moved(world):
    m, tA, tB, _ = world
    _enrol(m, tA, authority=None)
    grant, sig = make_grant(OWNER, TIK, CHIP_B)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "cannot be moved" in why

def test_a_grant_is_single_use(world):
    m, tA, tB, tC = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, CHIP_B)
    assert m.accept_transfer(TIK, grant, sig)[0]
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "already been used" in why

def test_an_expired_grant_is_refused(world):
    m, tA, _, _ = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, CHIP_B, valid_for=-1)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "validity window" in why

def test_a_grant_not_yet_valid_is_refused(world):
    m, tA, _, _ = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, CHIP_B, now=time.time() + 600)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "validity window" in why

def test_a_grant_from_the_wrong_key_is_refused(world):
    m, tA, _, _ = world
    _enrol(m, tA)
    grant, sig = make_grant(ROGUE, TIK, CHIP_B)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "transfer authority" in why

def test_a_grant_for_another_identity_is_refused(world):
    m, tA, _, _ = world
    _enrol(m, tA)
    _, other_pub = _key()
    grant, sig = make_grant(OWNER, other_pub, CHIP_B)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "different identity" in why

def test_a_tampered_grant_is_refused(world):
    m, tA, _, tC = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, CHIP_B)
    grant["to"] = CHIP_C.hex()                      # redirect it after signing
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "transfer authority" in why

def test_a_grant_pinned_to_a_different_current_instance_is_refused(world):
    m, tA, _, _ = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, CHIP_B, from_anchor=CHIP_C)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "different current instance" in why

def test_a_revoked_identity_cannot_be_transferred(world):
    m, tA, _, _ = world
    _enrol(m, tA); m.revoke(TIK, reason="key disclosed")
    grant, sig = make_grant(OWNER, TIK, CHIP_B)
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "revoked" in why

def test_cannot_transfer_onto_a_platform_with_no_anchor(world):
    m, tA, _, _ = world
    _enrol(m, tA)
    grant, sig = make_grant(OWNER, TIK, bytes(64))
    ok, why = m.accept_transfer(TIK, grant, sig)
    assert not ok and "no instance anchor" in why

def test_an_unenrolled_identity_cannot_be_transferred(world):
    m, _, _, _ = world
    grant, sig = make_grant(OWNER, TIK, CHIP_B)
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
    _enrol(m, tA)
    g1, s1 = make_grant(OWNER, TIK, CHIP_B); assert m.accept_transfer(TIK, g1, s1)[0]
    g2, s2 = make_grant(OWNER, TIK, CHIP_C); assert m.accept_transfer(TIK, g2, s2)[0]
    hist = m._rec(TIK.hex())["transfers"]
    assert [h["to"][:12] for h in hist] == [CHIP_B.hex()[:12], CHIP_C.hex()[:12]]
    assert hist[0]["from"] == CHIP_A.hex() and hist[1]["from"] == CHIP_B.hex()
