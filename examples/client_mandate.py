#!/usr/bin/env python3
"""HATLS client + shared Mandate, run on the operator machine against REAL guests.

Connects to each guest, drives a continuity chain, and feeds every step through the Mandate with
the REAL SEV-SNP verifier (VCEK from AMD KDS). Guest A is the victim; guest B holds the same TIK
on different silicon (re-hosting). The mandate must accept A's chain and REVOKE on B via chip-fork.
"""
import socket, ssl, json, struct, base64, hashlib, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for
from hatls.tee import sevsnp_verifier

def drive(ip, transcript_hex, steps=3, port=8443):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    raw=socket.create_connection((ip,port),timeout=30)
    tls=ctx.wrap_socket(raw,server_hostname="hatls")
    tls.send((json.dumps({"transcript":transcript_hex,"steps":steps})+"\n").encode())
    n=struct.unpack(">I",_recv(tls,4))[0]; blob=json.loads(_recv(tls,n)); tls.close()
    return blob
def _recv(s,n):
    b=b""
    while len(b)<n: b+=s.recv(n-len(b))
    return b

def main():
    ipA, ipB = sys.argv[1], sys.argv[2]
    transcript = hashlib.sha384(b"hatls-hw-run-"+str(int(time.time())).encode()).digest().hex()
    OUT=f"evidence/{time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())}"; os.makedirs(OUT,exist_ok=True)
    m=Mandate(sevsnp_verifier()); results=[]

    def feed(tag, blob, tik_pub, new_session):
        exp=bytes.fromhex(blob["exporter"])
        for step in blob["chain"]:
            msg={"counter":step["counter"],"post_link":step["post_link"],
                 "evidence":{"kind":"sev-snp","report":step["report"],
                             "report_data":report_data_for(bytes.fromhex(step["post_link"])).hex()}}
            ns = new_session and step["counter"]==0
            ok,why=m.present(tik_pub, bytes.fromhex(transcript), exp, msg, new_session=ns)
            results.append((tag,step["counter"],ok,why))
            print(f"   {tag} counter {step['counter']}: accepted={ok}  {why}")
            if not ok: break

    print(f"=== VICTIM: guest A ({ipA}) presents its continuity chain ===")
    bA=drive(ipA, transcript, steps=3); json.dump(bA,open(f"{OUT}/guestA.json","w"))
    tik=base64.b64decode(bA["tik_pub"])
    feed("A", bA, tik, new_session=True)

    print(f"\n=== RE-HOSTING: guest B ({ipB}) holds the SAME TIK on different silicon ===")
    bB=drive(ipB, transcript, steps=3); json.dump(bB,open(f"{OUT}/guestB.json","w"))
    tikB=base64.b64decode(bB["tik_pub"])
    print(f"   same TIK on both guests: {tik==tikB}")
    print(f"   guest A zone {bA['zone']}, guest B zone {bB['zone']}")
    feed("B", bB, tikB, new_session=True)

    print(f"\n=== VICTIM A tries to continue after the fork ===")
    bA2=drive(ipA, transcript, steps=1)
    feed("A-after", bA2, tik, new_session=True)

    print("\n--- mandate audit log ---")
    for e in m.log: print("   ",e)
    json.dump({"transcript":transcript,"results":results,"log":[list(map(str,e)) for e in m.log]},
              open(f"{OUT}/verdict.json","w"))
    print(f"\nevidence saved to {OUT}")

if __name__=="__main__": main()
