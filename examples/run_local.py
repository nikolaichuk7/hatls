#!/usr/bin/env python3
"""Full HATLS cycle, locally, MockTEE. Every scenario the hardware run must pass.

Key model point: the Mandate is a SHARED authority over an identity (like a transparency service),
so it sees the stolen key even when the attacker connects to a DIFFERENT Relying Party. The chip is
the non-copyable anchor: an attacker can steal the key AND the chain state, but not the silicon."""
import os, hashlib
from hatls.protocol import Attester, Mandate
from hatls.tee import MockTEE, mock_verifier

CHIP_A = (b"\xa2\xb2\x58\x0a"*16)[:64]
CHIP_B = (b"\x76\x10\x22\xd0"*16)[:64]
TIK    = b"victim-TIK-public-key-SPKI-fixed"

teeA, teeB = MockTEE(CHIP_A), MockTEE(CHIP_B)
verify = mock_verifier({teeA.pub.hex(), teeB.pub.hex()})   # both are genuine hardware

def line(ok, why): print(f"   accepted={ok!s:<5}  {why}")

print("=== 1. HONEST: one chip, handshake + 2 in-session re-attests ===")
m=Mandate(verify); a=Attester(teeA,TIK); exp=os.urandom(32); th=os.urandom(48)
ok,why=m.present(TIK,th,exp,a.attest(th,exp),new_session=True); line(ok,why)
for _ in range(2):
    ok,why=m.present(TIK,th,exp,a.attest(th,exp)); line(ok,why)

print("\n=== 2. LEGITIMATE RECONNECT: same chip, brand-new TLS session ===")
exp2=os.urandom(32); th2=os.urandom(48); a2=Attester(teeA,TIK)
ok,why=m.present(TIK,th2,exp2,a2.attest(th2,exp2),new_session=True); line(ok,why)
print("   (same identity, same chip, fresh session -> allowed)")

print("\n=== 3. RELAY: attacker relays; its client session has a different exporter ===")
m=Mandate(verify); a=Attester(teeA,TIK); expg=os.urandom(32); th=os.urandom(48)
m.present(TIK,th,expg,a.attest(th,expg),new_session=True)
expc=os.urandom(32)                                  # the client<->relay exporter differs
ok,why=m.present(TIK,th,expc,a.attest(th,expg))      # guest signed for expg, client checks expc
line(ok,why)

print("\n=== 4. RE-HOSTING, hardest case: attacker steals the TIK AND the full chain state ===")
m=Mandate(verify)
aA=Attester(teeA,TIK); exp=os.urandom(32); th=os.urandom(48)
ok,why=m.present(TIK,th,exp,aA.attest(th,exp),new_session=True); print("   victim, chip A:"); line(ok,why)
# attacker imports the key into ITS OWN genuine TEE and opens its own session to a (shared-mandate) RP.
# It even replays the victim's chain state; only the silicon differs.
aB=Attester(teeB,TIK); aB.prev=aA.prev; aB.counter=aA.counter
expX=os.urandom(32); thX=os.urandom(48)
ok,why=m.present(TIK,thX,expX,aB.attest(thX,expX),new_session=True); print("   attacker, chip B (stole key+state):"); line(ok,why)
ok,why=m.present(TIK,th,exp,aA.attest(th,exp)); print("   victim tries to continue:"); line(ok,why)

print("\n=== 5. REPLAY: resend an old in-session link ===")
m=Mandate(verify); a=Attester(teeA,TIK); exp=os.urandom(32); th=os.urandom(48)
m.present(TIK,th,exp,a.attest(th,exp),new_session=True)
step=a.attest(th,exp); m.present(TIK,th,exp,step)
ok,why=m.present(TIK,th,exp,step); print("   resent step:"); line(ok,why)

print("\n--- mandate audit log (re-hosting scenario) ---")
mm=Mandate(verify)
aA=Attester(teeA,TIK); e=os.urandom(32); t=os.urandom(48)
mm.present(TIK,t,e,aA.attest(t,e),new_session=True)
aB=Attester(teeB,TIK); aB.prev=aA.prev; aB.counter=aA.counter
mm.present(TIK,os.urandom(48),os.urandom(32),aB.attest(os.urandom(48),os.urandom(32)),new_session=True)
for ev in mm.log: print("   ",ev)

print("\n=== 6. ENROLLMENT PREVENTION: mandate knows TIK<->chip BEFORE any attack ===")
import hashlib as _h
m=Mandate(verify)
# enroll the victim key to chip A (TACRA-style: chip signs REPORT_DATA=SHA-512(nonce||csr))
nonce=os.urandom(32); csr=b"victim-CSR-DER-bytes"
enroll_rd=_h.sha512(nonce+csr).digest()
enroll_ev=teeA.report(enroll_rd)                      # chip A signs the enrollment
ok,why=m.enroll(TIK, enroll_ev, nonce, csr); print(f"   enroll on chip A: {ok} ({why})")
# NOW the attacker (chip B, stolen key) opens an INDEPENDENT session -- no victim active
aB=Attester(teeB,TIK); exp=os.urandom(32); th=os.urandom(48)
ok,why=m.present(TIK, th, exp, aB.attest(th,exp), new_session=True)
print(f"   attacker chip B, FIRST message, no victim present: accepted={ok}")
print(f"     -> {why}")
# and the legitimate victim on chip A still works
aA=Attester(teeA,TIK); exp=os.urandom(32); th=os.urandom(48)
ok,why=m.present(TIK, th, exp, aA.attest(th,exp), new_session=True)
print(f"   legitimate victim chip A: accepted={ok} ({why})")
