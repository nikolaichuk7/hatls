#!/usr/bin/env python3
"""HATLS client + shared Mandate, run on the operator machine against REAL SEV-SNP guests.

Guest A is the victim. Guest B holds the SAME identity key on different silicon: re-hosting.
This run uses NO enrolment, which is the weaker deployment, and shows what the mandate does when
it cannot tell owner from thief: it protects the incumbent chain, records the dispute, and REFUSES
to destroy the identity on an unauthenticated claim. (v0.1 revoked the victim here -- see
docs/AUDIT.md. Run enroll_run.py for the strong deployment, where B is blocked on its first
message and no dispute arises at all.)

Every binding value is derived locally: the exporter from our own TLS session, the identity key
from the certificate the guest proved possession of. Nothing security-relevant is read off the wire.
"""
import json, base64, hashlib, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for
from hatls.tee import sevsnp_verifier
from hatls.client import HatlsClient

def as_evidence(step):
    return {"counter": step["counter"], "post_link": step["post_link"]
            "evidence": {"kind":"sev-snp", "report": step["report"]
                         "report_data": report_data_for(bytes.fromhex(step["post_link"])).hex()}}

def run(m, ip, label, steps, results, out=None):
    with HatlsClient(ip, 8443) as cl:
        blob = cl.request({"steps": steps})
        if out: json.dump(blob, open(out, "w"))
        tik = cl.peer_identity_key
        last = None
        for step in blob["chain"]:
            ok, why = m.present(tik, cl.session_context, cl.exporter, as_evidence(step))
            results.append((label, step["counter"], ok, why)); last = ok
            print(f"   {label} counter {step['counter']}: accepted={ok}  {why}")
            if not ok: break
        return blob, last

def main():
    ipA, ipB = sys.argv[1], sys.argv[2]
    OUT = f"evidence/{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"; os.makedirs(OUT, exist_ok=True)
    m = Mandate(sevsnp_verifier()); results = []

    print(f"=== VICTIM: guest A ({ipA}) presents its continuity chain ===")
    bA, okA = run(m, ipA, "A", 3, results, f"{OUT}/guestA.json")

    print(f"\n=== RE-HOSTING: guest B ({ipB}) holds the SAME identity on different silicon ===")
    bB, okB = run(m, ipB, "B", 3, results, f"{OUT}/guestB.json")
    print(f"   guest A zone {bA['zone']}, guest B zone {bB['zone']}")

    print(f"\n=== THE VICTIM MUST SURVIVE THE IMPOSTOR ===")
    _, okA2 = run(m, ipA, "A-after", 1, results)

    print("\n--- mandate audit log ---")
    for e in m.log: print("   ", e)
    verdict = {"impostor_rejected": okB is False, "victim_still_serving": okA2 is True
               "contention_recorded": {k: v for k, v in m.contention.items()}
               "results": results, "log": [list(map(str, e)) for e in m.log]}
    json.dump(verdict, open(f"{OUT}/verdict.json", "w"), indent=1)
    print(f"\n  impostor rejected   : {verdict['impostor_rejected']}")
    print(f"  victim still serving: {verdict['victim_still_serving']}")
    print(f"\nevidence saved to {OUT}")
    return 0 if (verdict["impostor_rejected"] and verdict["victim_still_serving"]) else 1

if __name__ == "__main__": sys.exit(main())
