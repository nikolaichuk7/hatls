"""HATLS protocol tests: the honest path is accepted, every attack in the playground is stopped."""
import os, sys, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hatls.protocol import Attester, Mandate
from hatls.tee import MockTEE, mock_verifier

CHIP_A=(b"\xa2\xb2\x58\x0a"*16)[:64]; CHIP_B=(b"\x76\x10\x22\xd0"*16)[:64]
TIK=b"victim-TIK-public-key"

def _setup():
    tA=MockTEE(CHIP_A); tB=MockTEE(CHIP_B); v=mock_verifier({tA.pub.hex(), tB.pub.hex()})
    m=Mandate(v)
    nonce=os.urandom(32); csr=b"csr"
    m.enroll(TIK, tA.report(hashlib.sha512(nonce+csr).digest()), nonce, csr)
    return m, tA, tB

def test_honest_accepted():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,_=m.present(TIK,t,e,a.attest(t,e),new_session=True); assert ok

def test_rehost_blocked():
    m,_,tB=_setup(); a=Attester(tB,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e),new_session=True); assert not ok and "chip" in why

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
