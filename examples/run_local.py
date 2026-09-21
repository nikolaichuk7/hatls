#!/usr/bin/env python3
"""The full HATLS cycle, locally, on a MockTEE. Every scenario the hardware run must also pass.

Two model points. The mandate is a SHARED authority over an identity, so it sees a stolen key even
when the attacker opens its session to a DIFFERENT Relying Party. And the instance anchor is the
part an attacker cannot copy: it can steal the key and the chain state, but not the silicon --
provided the platform actually exposes an anchor, which scenario 7 shows is not always true.

Run:  PYTHONPATH=. python3 examples/run_local.py
"""
import os, hashlib, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr
from hatls.tee import MockTEE, mock_verifier

CHIP_A = (b"\xa2\xb2\x58\x0a"*16)[:64]
CHIP_B = (b"\x76\x10\x22\xd0"*16)[:64]
ZERO   = bytes(64)

TIK_PRIV = ec.generate_private_key(ec.SECP256R1())
TIK = TIK_PRIV.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
CSR = make_enrolment_csr(TIK_PRIV)          # self-signed: it IS the proof of possession

teeA, teeB = MockTEE(CHIP_A), MockTEE(CHIP_B)
verify = mock_verifier({teeA.pub.hex(), teeB.pub.hex()})   # both are genuine hardware

def line(ok, why): print(f"   accepted={ok!s:<5}  {why}")
def sess(): return os.urandom(48), os.urandom(32)          # a fresh (context, exporter) pair
def enrolled_mandate(tee=teeA, **kw):
    m=Mandate(verify, **kw); n=m.challenge()
    ok,why=m.enroll(TIK, tee.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert ok, why
    return m

print("=== 1. HONEST: one instance, handshake + 2 in-session re-attests ===")
m=enrolled_mandate(); a=Attester(teeA,TIK); c,e = sess()
for _ in range(3): line(*m.present(TIK,c,e,a.attest(c,e)))

print("\n=== 2. LEGITIMATE RECONNECT: same instance, brand-new TLS session ===")
c2,e2 = sess(); a2=Attester(teeA,TIK)
line(*m.present(TIK,c2,e2,a2.attest(c2,e2)))
print("   (same identity, same instance, fresh session -> allowed)")

print("\n=== 3. PARALLEL SESSIONS: one identity, two connections at once ===")
m=enrolled_mandate(); p1,q1 = sess(); p2,q2 = sess()
x1=Attester(teeA,TIK); x2=Attester(teeA,TIK)
m.present(TIK,p1,q1,x1.attest(p1,q1)); m.present(TIK,p2,q2,x2.attest(p2,q2))
print("   connection 1 continues after connection 2 opened:")
line(*m.present(TIK,p1,q1,x1.attest(p1,q1)))
print("   (continuity is tracked per connection; the ledger is per identity)")

print("\n=== 4. RELAY: the attacker relays genuine evidence, but its exporter differs ===")
m=enrolled_mandate(); a=Attester(teeA,TIK); c,eg = sess()
m.present(TIK,c,eg,a.attest(c,eg))
ec_ = os.urandom(32)                                 # the client<->relay exporter
line(*m.present(TIK,c,ec_,a.attest(c,eg)))           # guest signed for eg, verifier derived ec_
print("   (examples/relay_demo.py does this over real TLS, with a real relay)")

print("\n=== 5. RE-HOSTING, hardest case: the key AND the full chain state are stolen ===")
m=enrolled_mandate()
aA=Attester(teeA,TIK); c,e = sess()
print("   victim, instance A:"); line(*m.present(TIK,c,e,aA.attest(c,e)))
aB=Attester(teeB,TIK); aB.prev=aA.prev; aB.counter=aA.counter   # only the silicon differs
cX,eX = sess()
print("   attacker, instance B (stole key + state):"); line(*m.present(TIK,cX,eX,aB.attest(cX,eX)))
print("   victim carries on, untouched by the impostor:")
line(*m.present(TIK,c,e,aA.attest(c,e)))

print("\n=== 6. REPLAY: resend an old in-session link ===")
m=enrolled_mandate(); a=Attester(teeA,TIK); c,e = sess()
m.present(TIK,c,e,a.attest(c,e)); step=a.attest(c,e); m.present(TIK,c,e,step)
print("   resent step:"); line(*m.present(TIK,c,e,step))

print("\n=== 7. A PLATFORM WITH NO INSTANCE ANCHOR (AWS shared-tenancy VLEK) ===")
z1, z2 = MockTEE(ZERO), MockTEE(ZERO)                # two DIFFERENT machines, identical zeros
vz = mock_verifier({z1.pub.hex(), z2.pub.hex()})
mz = Mandate(vz); n=mz.challenge()
ok,why = mz.enroll(TIK, z1.report(hashlib.sha512(n+CSR).digest()), n, CSR)
print(f"   enrol on a masked platform: {ok} ({why})")
c,e = sess()
print("   stolen key on the OTHER masked machine:")
line(*mz.present(TIK,c,e,Attester(z2,TIK).attest(c,e)))
md = Mandate(vz, require_anchor=False); c,e = sess()
print("   same platform with the downgrade accepted explicitly:")
line(*md.present(TIK,c,e,Attester(z2,TIK).attest(c,e)))
print("   (ordering and relay defence still hold there; re-host detection does not)")

print("\n=== 8. ENROLMENT PREVENTION: the impostor is stopped on its FIRST message ===")
m=enrolled_mandate()
c,e = sess()
ok,why = m.present(TIK, c, e, Attester(teeB,TIK).attest(c,e))
print(f"   attacker instance B, first message, no victim present: accepted={ok}")
print(f"     -> {why}")
c,e = sess()
print("   the legitimate victim on its enrolled instance:")
line(*m.present(TIK, c, e, Attester(teeA,TIK).attest(c,e)))

print("\n=== 9. AN IMPOSTOR CANNOT RE-ENROL SOMEONE ELSE'S IDENTITY ===")
n=m.challenge()
ok,why = m.enroll(TIK, teeB.report(hashlib.sha512(n+CSR).digest()), n, CSR)
print(f"   attacker tries to enrol the victim's PUBLIC key on its own chip: {ok} ({why})")

print("\n=== 10. LEGITIMATE RECOVERY: the enrolled machine died, the owner says where to go ===")
from hatls.transfer import make_grant, authority_public_bytes
owner = ec.generate_private_key(ec.SECP256R1())
m = Mandate(verify); n = m.challenge()
ok, why = m.enroll(TIK, teeA.report(hashlib.sha512(n+CSR).digest()), n, CSR,
                   transfer_authority=authority_public_bytes(owner))
print(f"   enrolled on instance A, transfer authority named: {ok}")
c, e = sess()
print("   instance A dies; the operator relaunches on B, which is refused -- but now witnessed:")
line(*m.present(TIK, c, e, Attester(teeB,TIK).attest(c,e)))
grant, sig = make_grant(owner, TIK, teeB.instance, from_instance=teeA.instance)
ok, why = m.accept_transfer(TIK, grant, sig)
print(f"   the owner issues a single-use, time-bounded grant: {ok} ({why})")
c, e = sess()
print("   instance B now carries the identity:")
line(*m.present(TIK, c, e, Attester(teeB,TIK).attest(c,e)))
c, e = sess()
print("   and instance A, were it to come back, does not:")
line(*m.present(TIK, c, e, Attester(teeA,TIK).attest(c,e)))
print("   reusing the same grant a second time:")
line(*m.accept_transfer(TIK, grant, sig))

print("\n--- mandate audit log (scenario 8) ---")
for ev in m.log: print("   ", ev)
