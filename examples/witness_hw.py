#!/usr/bin/env python3
"""The chip as a witness to the mandate's ledger, on live SEV-SNP.

A transparency log makes the mandate's decisions non-repudiable, but the head of that log is still
the mandate's own word: it can sign two histories and each is well-formed on its own. Here the
verifier hands the attester its current ledger head, the guest binds it into REPORT_DATA, and AMD's
key signs across it. The report then says what this mandate claimed its ledger was at that moment,
and the mandate cannot mint a different one, because the signing key is the chip's.

Usage:  PYTHONPATH=. python3 examples/witness_hw.py <guest-ip>
"""
import json, base64, hashlib, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for, csr_public_key_der
from hatls.tee import sevsnp_verifier, parse_snp, snp_anchor
from hatls.client import HatlsClient
from hatls import receipt as R

def main():
    ip = sys.argv[1]
    OUT = f"evidence/witness-hw-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    os.makedirs(OUT, exist_ok=True)
    m = Mandate(sevsnp_verifier())
    out = {}

    print(f"=== 1. ENROLMENT on {ip} ===")
    with HatlsClient(ip, 8443) as cl:
        nonce = m.challenge()
        r = cl.request({"enroll": True, "nonce": nonce.hex()})
        csr = bytes.fromhex(r["csr"]); tik = cl.peer_identity_key
        assert csr_public_key_der(csr) == tik
        ev = {"kind": "sev-snp", "report": r["report"],
              "report_data": hashlib.sha512(nonce + csr).digest().hex()}
        ok, why = m.enroll(tik, ev, nonce, csr)
        a = snp_anchor(parse_snp(base64.b64decode(r["report"])))
        print(f"   zone {r['zone']}  instance {a['instance'].hex()[:16]}: enrolled={ok}")
        json.dump(r, open(f"{OUT}/enroll.json", "w"))
        if not ok: return 1

    print("\n=== 2. THE VERIFIER HANDS OVER ITS LEDGER HEAD, THE CHIP SIGNS ACROSS IT ===")
    head = m.head_for_attestation()
    print(f"   ledger size {len(m.merkle)}, head {head.hex()[:24]}")
    with HatlsClient(ip, 8443) as cl:
        blob = cl.request({"steps": 1, "head": head.hex()})
        json.dump(blob, open(f"{OUT}/witnessed.json", "w"))
        s = blob["chain"][0]
        msg = {"counter": 0, "post_link": s["post_link"],
               "evidence": {"kind": "sev-snp", "report": s["report"],
                            "report_data": report_data_for(bytes.fromhex(s["post_link"]),
                                                           head).hex()}}
        ok, why = m.present(tik, cl.session_context, cl.exporter, msg, head=head)
        print(f"   accepted={ok}  {why}")
        out["witnessed_accepted"] = ok
        rcpt = m.last_receipt
        rok, rwhy = R.verify_receipt(m.public_key, rcpt)
        print(f"   receipt verifies against the mandate's key: {rok} ({rwhy})")
        out["receipt_ok"] = rok
        json.dump({"receipt": rcpt, "mandate_pub": m.public_key.hex()},
                  open(f"{OUT}/receipt.json", "w"), indent=1)

    print("\n=== 3. WHAT AN AUDITOR CAN CHECK, HOLDING ONLY THE REPORT ===")
    raw = base64.b64decode(s["report"]); f = parse_snp(raw)
    signed_over = f["report_data"]
    print(f"   REPORT_DATA the chip signed : {signed_over.hex()[:32]}")
    print(f"   recomputed from link + head : {report_data_for(bytes.fromhex(s['post_link']), head).hex()[:32]}")
    matches = signed_over == report_data_for(bytes.fromhex(s["post_link"]), head)
    wrong = signed_over == report_data_for(bytes.fromhex(s["post_link"]), os.urandom(32))
    print(f"   the claimed head is the one AMD signed across : {matches}")
    print(f"   any other head would also match              : {wrong}")
    out["auditor_confirms_head"] = matches and not wrong

    print("\n=== 4. THE MANDATE CANNOT WALK IT BACK ===")
    ok_known = m.knows_head(head)
    print(f"   the mandate still accounts for the witnessed head: {ok_known}")
    m.merkle.entries = [R.make_entry("present", tik, True, "a different history", seq=0)]
    m._roots = {m.merkle.head().hex(): 1}
    print(f"   after rewriting its log, it accounts for it     : {m.knows_head(head)}")
    print("   -- and the chip's signature over that head is still out there, unforgeable")
    out["rewrite_detectable"] = ok_known and not m.knows_head(head)

    json.dump(out, open(f"{OUT}/verdict.json", "w"), indent=1)
    good = all(out.values())
    print(f"\n  RESULT: {'hardware witnessed the ledger head on real SEV-SNP' if good else '*** UNEXPECTED ***'}")
    print(f"  evidence -> {OUT}")
    return 0 if good else 1

if __name__ == "__main__": sys.exit(main())
