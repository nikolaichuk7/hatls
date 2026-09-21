#!/usr/bin/env python3
"""Enrolment prevention on live hardware: A enrols; B (same key, other chip) blocked FIRST message."""
import socket, ssl, json, struct, base64, hashlib, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for
from hatls.tee import sevsnp_verifier
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def rpc(ip, obj, port=8443):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    raw=socket.create_connection((ip,port),timeout=30); tls=ctx.wrap_socket(raw,server_hostname="hatls")
    tls.send((json.dumps(obj)+"\n").encode())
    n=struct.unpack(">I",_recv(tls,4))[0]; out=json.loads(_recv(tls,n)); tls.close(); return out
def _recv(s,n):
    b=b""
    while len(b)<n: b+=s.recv(n-len(b))
    return b

ipA, ipB = sys.argv[1], sys.argv[2]
OUT=f"evidence/enroll-{time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())}"; os.makedirs(OUT,exist_ok=True)

# the shared TIK (same file that launch.sh injected into BOTH guests)
tik_priv=serialization.load_pem_private_key(open("tik.key","rb").read(),None)
tik_pub=tik_priv.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
csr=b"HATLS-TIK-enrolment-CSR"          # stands for the CSR/CSKpub in TACRA
nonce=os.urandom(32)
m=Mandate(sevsnp_verifier())

print("=== ENROLMENT: guest A signs that this key lives on its chip ===")
eA=rpc(ipA, {"enroll":True,"nonce":nonce.hex(),"csr":csr.hex()})
json.dump(eA,open(f"{OUT}/enrollA.json","w"))
ev={"kind":"sev-snp","report":eA["report"],"report_data":hashlib.sha512(nonce+csr).digest().hex()}
ok,why=m.enroll(tik_pub, ev, nonce, csr)
chipA=base64.b64decode(eA["report"])[0x1A0:0x1E0].hex()[:16]
print(f"   guest A zone {eA['zone']}, chip {chipA}: enrolled={ok} ({why})")

print("\n=== ATTACK: guest B holds the same TIK, presents a continuity chain ===")
def drive(ip, transcript, steps=2):
    return rpc(ip, {"transcript":transcript,"steps":steps})
transcript=hashlib.sha384(b"enroll-test").digest().hex()
bB=drive(ipB, transcript, steps=2); json.dump(bB,open(f"{OUT}/guestB.json","w"))
chipB=base64.b64decode(bB["chain"][0]["report"])[0x1A0:0x1E0].hex()[:16]
print(f"   guest B zone {bB['zone']}, chip {chipB}, same TIK")
exp=bytes.fromhex(bB["exporter"])
step=bB["chain"][0]
msg={"counter":0,"post_link":step["post_link"],
     "evidence":{"kind":"sev-snp","report":step["report"],
                 "report_data":report_data_for(bytes.fromhex(step["post_link"])).hex()}}
ok,why=m.present(tik_pub, bytes.fromhex(transcript), exp, msg, new_session=True)
print(f"   attacker chip B, FIRST message, no victim active: accepted={ok}")
print(f"     -> {why}")

print("\n=== CONTROL: legitimate guest A on its enrolled chip ===")
bA=drive(ipA, transcript, steps=2); json.dump(bA,open(f"{OUT}/guestA.json","w"))
expA=bytes.fromhex(bA["exporter"]); sA=bA["chain"][0]
msgA={"counter":0,"post_link":sA["post_link"],
      "evidence":{"kind":"sev-snp","report":sA["report"],
                  "report_data":report_data_for(bytes.fromhex(sA["post_link"])).hex()}}
ok,why=m.present(tik_pub, bytes.fromhex(transcript), expA, msgA, new_session=True)
print(f"   victim chip A: accepted={ok} ({why})")

print("\n--- mandate log ---")
for e in m.log: print("   ",e)
json.dump({"log":[list(map(str,e)) for e in m.log]},open(f"{OUT}/verdict.json","w"))
print(f"\nevidence -> {OUT}")
