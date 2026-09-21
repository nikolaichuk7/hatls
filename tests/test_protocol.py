"""HATLS protocol tests.

The honest path is accepted; every attack in the playground is stopped; and the three defects the
21 Sep 2026 audit found stay fixed (see docs/AUDIT.md).
"""
import os, sys, hashlib, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr
from hatls.tee import MockTEE, mock_verifier

CHIP_A=(b"\xa2\xb2\x58\x0a"*16)[:64]; CHIP_B=(b"\x76\x10\x22\xd0"*16)[:64]; ZERO=bytes(64)

def _key():
    k=ec.generate_private_key(ec.SECP256R1())
    pub=k.public_key().public_bytes(serialization.Encoding.DER,
                                    serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pub, make_enrolment_csr(k)

TIK_PRIV, TIK, CSR = _key()

def _setup(chip=CHIP_A):
    tA=MockTEE(chip); tB=MockTEE(CHIP_B); v=mock_verifier({tA.pub.hex(), tB.pub.hex()})
    m=Mandate(v); n=m.challenge()
    ok,why=m.enroll(TIK, tA.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert ok, why
    return m, tA, tB

# ---------------- the original guarantees still hold ----------------
def test_honest_accepted():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e),new_session=True); assert ok, why

def test_rehost_blocked():
    m,_,tB=_setup(); a=Attester(tB,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e),new_session=True)
    assert not ok and "not enrolled" in why

def test_replay_blocked():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,e,a.attest(t,e),new_session=True); s=a.attest(t,e); m.present(TIK,t,e,s)
    ok,_=m.present(TIK,t,e,s); assert not ok

def test_relay_blocked():
    m,tA,_=_setup(); a=Attester(tA,TIK); eg=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,eg,a.attest(t,eg),new_session=True)
    ok,_=m.present(TIK,t,os.urandom(32),a.attest(t,eg)); assert not ok

def test_splice_blocked():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,e,a.attest(t,e),new_session=True); stolen=a.attest(t,e)
    ok,_=m.present(TIK,os.urandom(48),os.urandom(32),stolen,new_session=True); assert not ok

# ---------------- audit regressions: enrolment actually binds the key ----------------
def test_enrolment_hijack_refused():
    """An attacker knowing only the PUBLIC key must not be able to re-enrol it on his own chip."""
    m,tA,tB=_setup(); n=m.challenge()
    ok,why=m.enroll(TIK, tB.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert not ok and "already enrolled" in why
    a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    ok2,why2=m.present(TIK,t,e,a.attest(t,e),new_session=True)
    assert ok2, f"the rightful owner must remain usable, got: {why2}"

def test_enrolment_requires_a_csr_carrying_that_key():
    m,tA,_=_setup(); _,OTHER,OTHER_CSR=_key(); n=m.challenge()
    ok,why=m.enroll(OTHER, tA.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert not ok and "does not carry" in why

def test_enrolment_requires_proof_of_possession():
    m,tA,_=_setup(); _,OTHER,_o=_key(); n=m.challenge()
    ok,why=m.enroll(OTHER, tA.report(hashlib.sha512(n+b"not-a-csr").digest()), n, b"not-a-csr")
    assert not ok and "unusable" in why

def test_enrolment_nonce_cannot_be_replayed():
    m,tA,_=_setup(); _,OTHER,OTHER_CSR=_key(); stale=os.urandom(32)
    ok,why=m.enroll(OTHER, tA.report(hashlib.sha512(stale+OTHER_CSR).digest()), stale, OTHER_CSR)
    assert not ok and "not issued" in why

# ---------------- audit regressions: the anchor must exist ----------------
def test_masked_anchor_cannot_be_enrolled():
    z=MockTEE(ZERO); m=Mandate(mock_verifier({z.pub.hex()})); n=m.challenge()
    ok,why=m.enroll(TIK, z.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert not ok and "anchor" in why

def test_masked_anchor_fails_closed_on_present():
    """Two DIFFERENT machines both reporting an all-zero CHIP_ID (AWS shared-tenancy VLEK)."""
    z1=MockTEE(ZERO); z2=MockTEE(ZERO); m=Mandate(mock_verifier({z1.pub.hex(), z2.pub.hex()}))
    a=Attester(z2,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e),new_session=True)
    assert not ok and "anchor" in why

def test_masked_anchor_downgrade_is_explicit_and_logged():
    z=MockTEE(ZERO); m=Mandate(mock_verifier({z.pub.hex()}), require_anchor=False)
    a=Attester(z,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e),new_session=True)
    assert ok, why
    assert any(ev[0]=="anchor-absent-downgraded" for ev in m.log)

# ---------------- audit regressions: an impostor cannot revoke the victim ----------------
def test_impostor_cannot_revoke_the_victim():
    m,tA,tB=_setup(); t=os.urandom(48)
    victim=Attester(tA,TIK); ev=os.urandom(32)
    assert m.present(TIK,t,ev,victim.attest(t,ev),new_session=True)[0]
    thief=Attester(tB,TIK); et=os.urandom(32)
    ok,_=m.present(TIK,t,et,thief.attest(t,et),new_session=True); assert not ok
    ok2,why2=m.present(TIK,t,ev,victim.attest(t,ev))          # victim carries on
    assert ok2, f"victim must survive an impostor, got: {why2}"
    assert m.contention[TIK.hex()], "the dispute must still be recorded"

def test_revocation_is_an_explicit_operator_act():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    assert m.present(TIK,t,e,a.attest(t,e),new_session=True)[0]
    m.revoke(TIK, reason="key disclosed in incident 42")
    ok,why=m.present(TIK,t,e,a.attest(t,e)); assert not ok and "revoked" in why
