#!/usr/bin/env python3
"""Enrolment prevention on live hardware: A enrols; B (same key, other INSTANCE) is blocked on
its FIRST message, with no victim chain needed -- and without touching A's identity.

Identity is anchored on the instance claim (REPORT_ID), not on the silicon: two guests on one
socket share a CHIP_ID, and a shared-tenancy platform has none at all. The run prints both.

The enrolment credential is a real PKCS#10 CSR carrying the identity key and self-signed by it
(proof of possession), covered by a TEE report over a nonce THIS mandate issued. v0.1 used a
constant placeholder and never checked the key, so anyone knowing the public key could re-enrol
someone else's identity onto their own chip; see docs/AUDIT.md.
"""
import json, hashlib, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for, csr_public_key_der
from hatls.tee import sevsnp_verifier
from hatls.client import HatlsClient

def main():
    ipA, ipB = sys.argv[1], sys.argv[2]
    OUT = f"evidence/enroll-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"; os.makedirs(OUT, exist_ok=True)
    m = Mandate(sevsnp_verifier())

    print("=== ENROLMENT: guest A proves this key was born on its chip ===")
    with HatlsClient(ipA, 8443) as cl:
        nonce = m.challenge()
        r = cl.request({"enroll": True, "nonce": nonce.hex()})
        json.dump(r, open(f"{OUT}/enrollA.json", "w"))
        csr = bytes.fromhex(r["csr"])
        tik = cl.peer_identity_key
        if csr_public_key_der(csr) != tik:
            print("   ABORT: the CSR does not carry the key this TLS session authenticated"); return 1
        ev = {"kind": "sev-snp", "report": r["report"],
              "report_data": hashlib.sha512(nonce + csr).digest().hex()}
        ok, why = m.enroll(tik, ev, nonce, csr)
        from hatls.tee import parse_snp, snp_anchor
        import base64 as _b
        aA = snp_anchor(parse_snp(_b.b64decode(r["report"])))
        print(f"   guest A zone {r['zone']}: instance {aA['instance'].hex()[:16]}, "
              f"place {aA['place'].hex()[:16] if aA['place'] else 'masked'}")
        print(f"   enrolled={ok} ({why})")
        if not ok: return 1

    print("\n=== ATTACK: guest B holds the same identity key, presents a chain ===")
    with HatlsClient(ipB, 8443) as cl:
        blob = cl.request({"steps": 2}); json.dump(blob, open(f"{OUT}/guestB.json", "w"))
        if cl.peer_identity_key != tik:
            print("   (guest B is serving a different key; not the re-hosting case)"); return 1
        step = blob["chain"][0]
        msg = {"counter": 0, "post_link": step["post_link"],
               "evidence": {"kind": "sev-snp", "report": step["report"],
                            "report_data": report_data_for(bytes.fromhex(step["post_link"])).hex()}}
        okB, whyB = m.present(tik, cl.session_context, cl.exporter, msg)
        print(f"   guest B zone {blob['zone']}, FIRST message, no victim active: accepted={okB}")
        print(f"     -> {whyB}")

    print("\n=== CONTROL: the legitimate guest A on its enrolled chip ===")
    with HatlsClient(ipA, 8443) as cl:
        blob = cl.request({"steps": 2}); json.dump(blob, open(f"{OUT}/guestA.json", "w"))
        step = blob["chain"][0]
        msg = {"counter": 0, "post_link": step["post_link"],
               "evidence": {"kind": "sev-snp", "report": step["report"],
                            "report_data": report_data_for(bytes.fromhex(step["post_link"])).hex()}}
        okA, whyA = m.present(cl.peer_identity_key, cl.session_context, cl.exporter, msg)
        print(f"   victim chip A: accepted={okA} ({whyA})")

    print("\n--- mandate log ---")
    for e in m.log: print("   ", e)
    json.dump({"impostor_blocked_first_message": okB is False, "victim_accepted": okA is True,
               "log": [list(map(str, e)) for e in m.log]}, open(f"{OUT}/verdict.json", "w"), indent=1)
    print(f"\nevidence -> {OUT}")
    return 0 if (okB is False and okA is True) else 1

if __name__ == "__main__": sys.exit(main())
