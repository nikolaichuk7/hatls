"""The mandate's ledger must survive a restart, and must never downgrade in silence.

Two separate failures were possible, and they need separate guards:
  * losing the ledger, which a durable store fixes;
  * not noticing it was lost, which only an explicit policy fixes, because an empty ledger and a
    deliberately unenrolled identity look identical from inside present().
"""
import os, sys, time, hashlib, tempfile, shutil, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr
from hatls.store import MemoryStore, FileStore
from hatls.tee import MockTEE, mock_verifier

CHIP_A = (b"\xa2\xb2\x58\x0a" * 16)[:64]
CHIP_B = (b"\x76\x10\x22\xd0" * 16)[:64]

def _key():
    k = ec.generate_private_key(ec.SECP256R1())
    pub = k.public_key().public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pub, make_enrolment_csr(k)

KEY, TIK, CSR = _key()

@pytest.fixture
def ledger_dir():
    d = tempfile.mkdtemp(prefix="hatls-ledger-")
    yield d
    shutil.rmtree(d, ignore_errors=True)

def _mandate(store, **kw):
    tA, tB = MockTEE(CHIP_A), MockTEE(CHIP_B)
    return Mandate(mock_verifier({tA.pub.hex(), tB.pub.hex()}), store=store, **kw), tA, tB

def _enrol(m, tee):
    n = m.challenge()
    ok, why = m.enroll(TIK, tee.report(hashlib.sha512(n + CSR).digest()), n, CSR)
    assert ok, why

def _present(m, tee):
    c, e = os.urandom(48), os.urandom(32)
    return m.present(TIK, c, e, Attester(tee, TIK).attest(c, e))

# ---------------- durability ----------------
def test_the_default_store_is_not_durable_and_says_so():
    m, _, _ = _mandate(MemoryStore())
    assert m.durable is False

def test_a_file_backed_ledger_survives_a_restart(ledger_dir):
    m, tA, tB = _mandate(FileStore(ledger_dir))
    assert m.durable is True
    _enrol(m, tA)
    restarted, tA2, tB2 = _mandate(FileStore(ledger_dir))       # the process comes back
    assert TIK.hex() in restarted.enrolled, "the enrolment record must survive"
    # the verifier of the restarted mandate trusts different mock keys, so re-point it
    restarted.verify_report = mock_verifier({tA.pub.hex(), tB.pub.hex()})
    ok, why = _present(restarted, tB)
    assert not ok and "not enrolled" in why, "the impostor must still be blocked after a restart"
    ok2, why2 = _present(restarted, tA)
    assert ok2, f"the rightful owner must still be served after a restart: {why2}"

def test_revocation_survives_a_restart(ledger_dir):
    m, tA, _ = _mandate(FileStore(ledger_dir))
    _enrol(m, tA); m.revoke(TIK, reason="incident 42")
    restarted, _, _ = _mandate(FileStore(ledger_dir))
    restarted.verify_report = m.verify_report
    ok, why = _present(restarted, tA)
    assert not ok and "revoked" in why

def test_contention_survives_a_restart(ledger_dir):
    m, tA, tB = _mandate(FileStore(ledger_dir))
    _enrol(m, tA); _present(m, tB)                       # an impostor shows up
    assert m.contention[TIK.hex()]
    restarted, _, _ = _mandate(FileStore(ledger_dir))
    assert restarted.contention[TIK.hex()], "the dispute must outlive the process that saw it"

# ---------------- no silent downgrade ----------------
def test_require_enrolment_refuses_an_identity_the_ledger_does_not_know():
    """This is the guard that a durable store cannot provide: if the ledger is empty because it was
    lost, an impostor would otherwise be served under the weaker no-enrolment rules."""
    m, tA, tB = _mandate(MemoryStore(), require_enrolment=True)
    ok, why = _present(m, tB)
    assert not ok and "no enrolment on record" in why
    ok2, why2 = _present(m, tA)
    assert not ok2, "not even the rightful owner is served from an empty ledger under this policy"

def test_require_enrolment_serves_an_enrolled_identity_normally():
    m, tA, tB = _mandate(MemoryStore(), require_enrolment=True)
    _enrol(m, tA)
    assert _present(m, tA)[0]
    assert not _present(m, tB)[0]

def test_a_wiped_ledger_is_refused_rather_than_downgraded(ledger_dir):
    m, tA, tB = _mandate(FileStore(ledger_dir), require_enrolment=True)
    _enrol(m, tA)
    for f in os.listdir(ledger_dir): os.unlink(os.path.join(ledger_dir, f))   # the ledger is lost
    restarted, _, _ = _mandate(FileStore(ledger_dir), require_enrolment=True)
    restarted.verify_report = m.verify_report
    ok, why = _present(restarted, tB)
    assert not ok and "no enrolment on record" in why

# ---------------- the store itself ----------------
def test_writes_are_atomic_and_leave_no_debris(ledger_dir):
    st = FileStore(ledger_dir)
    for i in range(20): st.put("ab" * 16, {"n": i})
    assert st.get("ab" * 16) == {"n": 19}
    assert [f for f in os.listdir(ledger_dir) if f.endswith(".tmp")] == []
    assert st.keys() == ["ab" * 16]

def test_the_store_refuses_a_key_that_is_not_hex(ledger_dir):
    with pytest.raises(ValueError):
        FileStore(ledger_dir).put("../escape", {"x": 1})

def test_an_unissued_or_expired_nonce_is_refused():
    m, tA, _ = _mandate(MemoryStore(), challenge_ttl=0)
    n = m.challenge()
    time.sleep(0.01)
    ok, why = m.enroll(TIK, tA.report(hashlib.sha512(n + CSR).digest()), n, CSR)
    assert not ok and "expired" in why
