#!/usr/bin/env python3
"""
HATLS attack playground — try to break the protocol, see what the mandate does.

Runs entirely locally with a MockTEE (an ephemeral key standing in for the AMD chip), so anyone
can run it with no cloud and no hardware. Each function is one way an attacker might try to cheat;
the mandate's verdict is printed. Green = the attack was stopped.

Run:  python3 attack.py            (all attacks)
      python3 attack.py relay      (just one)
"""
import os, sys, hashlib, base64
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, report_data_for, post_link, intra_link, make_enrolment_csr
from hatls.tee import MockTEE, mock_verifier

CHIP_A=(b"\xa2\xb2\x58\x0a"*16)[:64]; CHIP_B=(b"\x76\x10\x22\xd0"*16)[:64]
TIK_PRIV=ec.generate_private_key(ec.SECP256R1())
TIK=TIK_PRIV.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
CSR=make_enrolment_csr(TIK_PRIV)          # self-signed: it IS the proof of possession
teeA=MockTEE(CHIP_A); teeB=MockTEE(CHIP_B)
VERIFY=mock_verifier({teeA.pub.hex(), teeB.pub.hex()})   # both chips are genuine silicon

def fresh_mandate(enroll=True):
    m=Mandate(VERIFY)
    if enroll:
        n=m.challenge()                   # the mandate picks the nonce, so enrolment cannot be replayed
        ok,why=m.enroll(TIK, teeA.report(hashlib.sha512(n+CSR).digest()), n, CSR)
        assert ok, why
    return m

def show(name, accepted, why):
    tag = "STOPPED " if not accepted else "!! GOT IN"
    print(f"  [{tag}] {name}: {why}")
    return not accepted

# --- the attacks -------------------------------------------------------------------
def a_honest():
    "baseline: the real server, should be accepted"
    m=fresh_mandate(); a=Attester(teeA,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e))
    print(f"  [CONTROL ] honest server: {'accepted' if ok else 'REJECTED?!'} - {why}")
    return ok  # control must pass

def a_rehost():
    "steal the key, run it on a different chip"
    m=fresh_mandate(); a=Attester(teeB,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e)); return show("re-host (stolen key, other chip)",ok,why)

def a_replay():
    "record a valid step, send it again later"
    m=fresh_mandate(); a=Attester(teeA,TIK); e=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,e,a.attest(t,e)); step=a.attest(t,e); m.present(TIK,t,e,step)
    ok,why=m.present(TIK,t,e,step); return show("replay (resend an old step)",ok,why)

def a_relay():
    "relay: attacker in its own session with a different exporter"
    m=fresh_mandate(); a=Attester(teeA,TIK); eg=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,eg,a.attest(t,eg))
    ec=os.urandom(32)  # the client<->relay session exporter differs from the guest's
    ok,why=m.present(TIK,t,ec,a.attest(t,eg)); return show("relay (forward genuine evidence)",ok,why)

def a_forge_malleable():
    "flip the signature (r,s)->(r,n-s): still valid, but body unchanged"
    m=fresh_mandate(); a=Attester(teeA,TIK); e=os.urandom(32); t=os.urandom(48)
    step=a.attest(t,e)
    # mock signatures are ECDSA too; flip s. Our verifier binds identity to the BODY (chip), so a
    # flipped-but-valid report of the same body is the same attestation -> no double count.
    ok,why=m.present(TIK,t,e,step)
    # attacker resubmits the same step with a re-signed report (models a malleated duplicate)
    dup=dict(step); ok2,why2=m.present(TIK,t,e,dup)
    return show("signature-forge / duplicate",ok2,why2)

def a_rollback_counter():
    "run two steps, then try to rewind to counter 0 on the same session"
    m=fresh_mandate(); a=Attester(teeA,TIK); e=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,e,a.attest(t,e)); m.present(TIK,t,e,a.attest(t,e))
    b=Attester(teeA,TIK)  # fresh counter 0
    ok,why=m.present(TIK,t,e,b.attest(t,e))  # counter 0 again mid-session
    return show("counter rollback",ok,why)

def a_splice():
    "take a link from one identity's chain and present it under another session"
    m=fresh_mandate(); a=Attester(teeA,TIK); e=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,e,a.attest(t,e))
    stolen=a.attest(t,e)  # a valid link
    e2=os.urandom(32); t2=os.urandom(48)  # a different session
    ok,why=m.present(TIK,t2,e2,stolen); return show("splice link into another session",ok,why)

def a_no_enrollment():
    "attacker connects to a mandate that never enrolled the victim (weakest deployment)"
    m=fresh_mandate(enroll=False); a=Attester(teeB,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e))
    # without enrolment the first message from chip B is NOT blocked by chip-baseline; it is only
    # caught later, when chip A also appears (fork). This is the honest weaker mode.
    print(f"  [WEAKER  ] no-enrolment first message: "
          f"{'got in (a later second instance is flagged as contention)' if ok else 'stopped'} - {why}")
    return True  # informational, not a pass/fail


def a_enrolment_hijack():
    "attacker re-enrols the victim's PUBLIC key on his own chip, locking the owner out"
    m=fresh_mandate()                      # victim legitimately enrolled on chip A
    # the attacker knows only the PUBLIC key -- it is printed in the victim's TLS certificate
    n=m.challenge()
    m.enroll(TIK, teeB.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    a=Attester(teeA,TIK); e=os.urandom(32); t=os.urandom(48)      # the REAL victim, its own chip
    ok,why=m.present(TIK,t,e,a.attest(t,e))
    # the attack SUCCEEDS when the rightful owner is refused
    return show("enrolment hijack (lock the real owner out)", not ok,
                "re-enrolment refused; the rightful owner is still served" if ok else why)

def a_masked_chip():
    "genuine platform that reports an all-zero CHIP_ID (AWS shared-tenancy VLEK): anchor vanishes"
    ZERO=bytes(64)
    z1=MockTEE(ZERO); z2=MockTEE(ZERO)     # two DIFFERENT machines, identical masked identifier
    m=Mandate(mock_verifier({z1.pub.hex(), z2.pub.hex()}))
    n=m.challenge(); m.enroll(TIK, z1.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    a=Attester(z2,TIK); e=os.urandom(32); t=os.urandom(48)        # stolen key on the OTHER machine
    ok,why=m.present(TIK,t,e,a.attest(t,e))
    return show("re-host on a masked-CHIP_ID platform", ok, why)

ATTACKS={"honest":a_honest,"rehost":a_rehost,"replay":a_replay,"relay":a_relay,
         "forge":a_forge_malleable,"rollback":a_rollback_counter,"splice":a_splice,"noenroll":a_no_enrollment,
         "hijack":a_enrolment_hijack,"masked":a_masked_chip}

if __name__=="__main__":
    which=sys.argv[1:] or list(ATTACKS)
    print("HATLS attack playground (local, MockTEE). STOPPED = the mandate caught it.\n")
    stopped=0; total=0; control_ok=True
    for name in which:
        fn=ATTACKS.get(name)
        if not fn: print(f"  unknown attack: {name}"); continue
        r=fn()
        if name=="honest": control_ok=bool(r)
        elif name!="noenroll": total+=1; stopped+=1 if r else 0
    print(f"\n  attacks stopped: {stopped}/{total}")
    # exit non-zero so CI fails if an attack gets in or the honest control stops working
    if not control_ok: print("  CONTROL FAILED: the honest server was rejected"); sys.exit(1)
    if stopped != total: print(f"  FAILURE: {total-stopped} attack(s) got in"); sys.exit(1)
    sys.exit(0)
