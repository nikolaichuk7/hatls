#!/usr/bin/env python3
"""Measured performance and correctness of the continuity layer.

Everything here runs on a MockTEE so it reproduces anywhere in seconds; the numbers are about the
continuity layer itself, which is the part HATLS adds. Appraising real Evidence costs whatever the
TEE verifier costs (KDS fetch, ECDSA over the report) and is measured separately on hardware.

Run:  PYTHONPATH=. python3 bench/benchmark.py
"""
import os, sys, time, hashlib, statistics
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, post_link, intra_link, make_enrolment_csr
from hatls.tee import MockTEE, mock_verifier

N = int(os.environ.get("HATLS_BENCH_N", "500"))
CHIP_A=(b"\xa2\xb2\x58\x0a"*16)[:64]; CHIP_B=(b"\x76\x10\x22\xd0"*16)[:64]
K = ec.generate_private_key(ec.SECP256R1())
TIK = K.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
CSR = make_enrolment_csr(K)
teeA, teeB = MockTEE(CHIP_A), MockTEE(CHIP_B)
VERIFY = mock_verifier({teeA.pub.hex(), teeB.pub.hex()})

def enrolled():
    m=Mandate(VERIFY); n=m.challenge()
    ok,why=m.enroll(TIK, teeA.report(hashlib.sha512(n+CSR).digest()), n, CSR); assert ok, why
    return m

def timed(fn, reps):
    t0=time.perf_counter()
    for _ in range(reps): fn()
    return (time.perf_counter()-t0)/reps

print(f"HATLS continuity layer -- {N} trials per correctness test\n")

# --- cost of one link ---
base=intra_link(os.urandom(48), TIK); exp=os.urandom(32)
per_link = timed(lambda: post_link(exp, base, 7), 200_000)
print(f"link derivation          : {per_link*1e6:6.2f} us   ({1/per_link:,.0f}/sec)")

# --- cost of one mandate check (includes the mock ECDSA verify) ---
m=enrolled(); a=Attester(teeA,TIK); c,e = os.urandom(48), os.urandom(32)
steps=[a.attest(c,e) for _ in range(2000)]; i=iter(steps)
per_check = timed(lambda: m.present(TIK,c,e,next(i)), 2000)
print(f"mandate check (w/ ECDSA) : {per_check*1e3:6.3f} ms   ({1/per_check:,.0f}/sec per core)")

# --- correctness 1: legitimate reconnects from the enrolled instance ---
false_rejects=0
for _ in range(N):
    m=enrolled(); c,e = os.urandom(48), os.urandom(32)
    ok,_=m.present(TIK,c,e,Attester(teeA,TIK).attest(c,e))
    false_rejects += 0 if ok else 1
print(f"\nlegitimate reconnects    : {false_rejects} false rejects / {N}")

# --- correctness 2: stolen key presented from a different instance ---
missed=0
for _ in range(N):
    m=enrolled(); c,e = os.urandom(48), os.urandom(32)
    ok,_=m.present(TIK,c,e,Attester(teeB,TIK).attest(c,e))
    missed += 1 if ok else 0
print(f"stolen key, other chip   : {missed} missed / {N}")

# --- correctness 3: ordinary in-session traffic must not break the chain ---
breaks=0
m=enrolled(); a=Attester(teeA,TIK); c,e = os.urandom(48), os.urandom(32)
for _ in range(N):
    ok,_=m.present(TIK,c,e,a.attest(c,e))
    breaks += 0 if ok else 1
print(f"in-session steps         : {breaks} false breaks / {N}")

# --- correctness 4: parallel connections from one identity ---
m=enrolled(); pairs=[(os.urandom(48), os.urandom(32)) for _ in range(16)]
atts=[Attester(teeA,TIK) for _ in pairs]; par_breaks=0
for round_ in range(N//16):
    for (cc,ee),at in zip(pairs,atts):
        ok,_=m.present(TIK,cc,ee,at.attest(cc,ee))
        par_breaks += 0 if ok else 1
print(f"16 parallel connections  : {par_breaks} false breaks / {(N//16)*16}")

# --- correctness 5: a relayed exporter must never be accepted ---
relay_in=0
for _ in range(N):
    m=enrolled(); c,eg = os.urandom(48), os.urandom(32)
    m.present(TIK,c,eg,(g:=Attester(teeA,TIK)).attest(c,eg))
    ok,_=m.present(TIK,c,os.urandom(32),g.attest(c,eg))     # verifier's own exporter differs
    relay_in += 1 if ok else 0
print(f"relayed exporter         : {relay_in} accepted / {N}")
