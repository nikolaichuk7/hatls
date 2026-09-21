#!/usr/bin/env python3
"""Two mandates over one identity, on live SEV-SNP, with the attester as the channel.

Preventing two mandates from diverging needs consensus. Detecting it needs only that their claims
meet somewhere. In Certificate Transparency the unsolved part of exactly this is gossip. Here both
mandates already trust the same TEE -- that is the whole point of the system -- and that TEE will
sign over whatever it is shown.

So one hardware report carries BOTH mandates' claimed ledger heads, at one moment, under AMD's key,
which belongs to neither of them. Afterwards either mandate, an auditor, or the workload owner can
hold that one report and ask each mandate to show its log extends what the chip saw.

Usage:  PYTHONPATH=. python3 examples/federation_hw.py <guest-ip>
"""
import json, base64, hashlib, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for, csr_public_key_der
from hatls.tee import sevsnp_verifier, parse_snp, snp_anchor
from hatls.client import HatlsClient
from hatls import federation as F, receipt as R

def enrol(m, cl, tik, label):
    nonce = m.challenge()
    r = cl.request({"enroll": True, "nonce": nonce.hex()})
    csr = bytes.fromhex(r["csr"])
    assert csr_public_key_der(csr) == tik, "CSR does not carry the TLS peer key"
    ev = {"kind": "sev-snp", "report": r["report"],
          "report_data": hashlib.sha512(nonce + csr).digest().hex()}
    ok, why = m.enroll(tik, ev, nonce, csr)
    print(f"   mandate {label} ({m.id[:8]}): enrolled={ok}")
    return ok, r

def main():
    ip = sys.argv[1]
    OUT = f"evidence/federation-hw-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    os.makedirs(OUT, exist_ok=True)
    v = sevsnp_verifier()
    A, B = Mandate(v), Mandate(v)
    out = {}

    print(f"=== 1. TWO INDEPENDENT MANDATES ENROL THE SAME IDENTITY ({ip}) ===")
    with HatlsClient(ip, 8443) as cl:
        tik = cl.peer_identity_key
        okA, rA = enrol(A, cl, tik, "A")
    with HatlsClient(ip, 8443) as cl:
        okB, rB = enrol(B, cl, tik, "B")
    json.dump({"A": rA, "B": rB}, open(f"{OUT}/enrol.json", "w"))
    inst = snp_anchor(parse_snp(base64.b64decode(rA["report"])))["instance"]
    print(f"   both anchored on instance {inst.hex()[:16]}")
    out["enrolled_both"] = okA and okB
    if not out["enrolled_both"]: return 1

    print("\n=== 2. ONE ATTESTATION CARRIES BOTH HEADS, SIGNED BY THE CHIP ===")
    commitment, entries = F.make_bundle([(A.public_key, A.sth()), (B.public_key, B.sth())])
    print(f"   bundle: {[(e['m'][:8], e['size'], e['root'][:12]) for e in entries]}")
    print(f"   commitment the guest will bind: {commitment.hex()[:24]}")
    with HatlsClient(ip, 8443) as cl:
        blob = cl.request({"steps": 1, "head": commitment.hex()})
        json.dump({"blob": blob, "entries": entries}, open(f"{OUT}/witnessed.json", "w"))
        s = blob["chain"][0]
        msg = {"counter": 0, "post_link": s["post_link"],
               "evidence": {"kind": "sev-snp", "report": s["report"],
                            "report_data": report_data_for(bytes.fromhex(s["post_link"]),
                                                           commitment).hex()}}
        okA2, whyA2 = A.present(tik, cl.session_context, cl.exporter, msg,
                                head=commitment, bundle=entries)
        okB2, whyB2 = B.present(tik, cl.session_context, cl.exporter, msg,
                                head=commitment, bundle=entries)
    print(f"   mandate A accepts: {okA2}  {whyA2}")
    print(f"   mandate B accepts: {okB2}  {whyB2}")
    out["both_accepted"] = okA2 and okB2

    print("\n=== 3. WHAT THE REPORT PROVES, TO ANYONE ===")
    f = parse_snp(base64.b64decode(s["report"]))
    rebuilt = report_data_for(bytes.fromhex(s["post_link"]), F.bundle_commitment(entries))
    print(f"   REPORT_DATA signed by AMD  : {f['report_data'].hex()[:32]}")
    print(f"   rebuilt from link + bundle : {rebuilt.hex()[:32]}")
    print(f"   the bundle is the one the chip signed across: {f['report_data'] == rebuilt}")
    out["auditor_confirms_bundle"] = f["report_data"] == rebuilt

    print("\n=== 4. MANDATE A REWRITES ITS LOG ===")
    witnessed = F.entry_for(entries, A.public_key)
    A.merkle.entries = [R.make_entry("present", tik, True, "a different history", seq=0)]
    A._roots = {A.merkle.head().hex(): 1}
    try: proof = A.prove_extension(witnessed["size"])
    except Exception: proof = None
    diverged, why = F.divergence(A.public_key, witnessed["size"], witnessed["root"], A.sth(), proof)
    print(f"   diverged={diverged}")
    print(f"     {why}")
    print("   B never trusted A, and no consensus ran: the chip's report is the whole evidence.")
    out["divergence_detected"] = diverged

    json.dump(out, open(f"{OUT}/verdict.json", "w"), indent=1)
    good = all(out.values())
    print(f"\n  RESULT: {'two mandates reconciled through the attester on real SEV-SNP' if good else '*** UNEXPECTED ***'}")
    print(f"  evidence -> {OUT}")
    return 0 if good else 1

if __name__ == "__main__": sys.exit(main())
