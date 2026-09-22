#!/usr/bin/env python3
"""Reattestation freshness on real SEV-SNP silicon.

draft-fossati-seat-early-attestation-07, Section 8.4, states the gap in prose:

    "an attester, whether malicious or due to an incorrect implementation, could resend
     Evidence generated earlier in the connection in response to a later reattestation
     request, since the binder still matches and the Relying Party has no way to
     distinguish it from fresh Evidence."
    "... The mechanism will be defined in future revisions."

This run measures both halves of that sentence on a real confidential VM, with real
AMD-signed Evidence, nothing forged:

  A. CONSTANT BINDER (the draft's Section 5.1 shape). The guest emits two genuine reports
     in one connection, both binding the one binder that connection derived. We check the
     two reports are authentic and then ask: can a Relying Party that appraises the binder
     tell round 1's report from round 0's? Section 8.4 says no. We measure whether that
     holds byte for byte.

  B. CHAINED BINDER (what this repository does). Same guest, same silicon, same session
     shape, but each link is HKDF(exporter, prev_link || counter). We replay round 0's
     genuine report at round 1 and see what the mandate does with it.

HONEST SCOPE. Our constant binder is derived from the session's exporter, not from the
ClientHello..ServerHello transcript the draft specifies. The property under test is that
the binder is CONSTANT for the connection's lifetime, which both derivations share; the
Section 8.4 defect follows from constancy alone, not from where the constant came from.
Nothing here is a claim about the draft's transcript derivation.

Usage:  PYTHONPATH=. python3 examples/reattest_freshness_hw.py <guest-ip>
"""
import os, sys, json, base64, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for, intra_link
from hatls.tee import sevsnp_verifier, parse_snp, snp_anchor
from hatls.client import HatlsClient

REPORT_DATA, MEASUREMENT, CHIP_ID, REPORT_ID = 0x50, 0x90, 0x1A0, 0x140

def field(rep, off, n):
    return rep[off:off+n]

def main(ip):
    import time
    verify = sevsnp_verifier(require_chain=True)
    OUT = f"evidence/reattest-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    os.makedirs(OUT, exist_ok=True)
    print(f"guest {ip}:8443 — real AMD SEV-SNP confidential VM")
    print(f"evidence -> {OUT}\n")

    # ---------------------------------------------------------------- A. constant binder
    print("A. CONSTANT BINDER  (draft-fossati-seat-early-attestation Sec. 5.1 shape)")
    with HatlsClient(ip, 8443) as c:
        blob = c.request({"static": True, "steps": 2})
    rounds = blob["rounds"]
    r0 = base64.b64decode(rounds[0]["report"]); r1 = base64.b64decode(rounds[1]["report"])
    print(f"   instance                 {blob['instance']} @ {blob['zone']}")
    print(f"   two genuine reports, {len(r0)} bytes each, emitted in ONE connection")

    binder = bytes.fromhex(rounds[0]["binder"])
    ok0, anc0 = verify({"kind": "sev-snp", "report": rounds[0]["report"]}, report_data_for(binder))
    ok1, anc1 = verify({"kind": "sev-snp", "report": rounds[1]["report"]}, report_data_for(binder))
    print(f"   round 0 authentic (VCEK -> ASK -> ARK)   {ok0}")
    print(f"   round 1 authentic (VCEK -> ASK -> ARK)   {ok1}")
    if not (ok0 and ok1):
        print("   ABORT: a report failed appraisal; nothing below is meaningful"); return 1
    print(f"   instance anchor          {anc0['instance'].hex()[:32]}...")

    d0, d1 = field(r0, REPORT_DATA, 64), field(r1, REPORT_DATA, 64)
    print(f"   REPORT_DATA round 0      {d0.hex()[:48]}...")
    print(f"   REPORT_DATA round 1      {d1.hex()[:48]}...")
    print(f"   REPORT_DATA identical    {d0 == d1}")
    print(f"   whole report identical   {r0 == r1}   (signatures are randomised)")
    same = [n for n, o, l in (("MEASUREMENT", MEASUREMENT, 48), ("CHIP_ID", CHIP_ID, 64),
                              ("REPORT_ID", REPORT_ID, 32))
            if field(r0, o, l) == field(r1, o, l)]
    print(f"   fields equal in both     {', '.join(same)}")

    # the Section 8.4 attacker: answer the round-1 request with round 0's genuine report.
    accepted, _ = verify({"kind": "sev-snp", "report": rounds[0]["report"]}, report_data_for(binder))
    print(f"\n   Sec 8.4 attack: resend round 0's Evidence when round 1 is requested")
    print(f"   binder-only appraisal    {'ACCEPTED  <-- the gap, measured' if accepted else 'rejected'}")

    # ---------------------------------------------------------------- B. chained binder
    print("\nB. CHAINED BINDER  (this repository)")
    m = Mandate(verify, require_anchor=True)
    with HatlsClient(ip, 8443) as c:
        exporter, sc, tik = c.exporter, c.session_context, c.peer_identity_key
        chain = c.request({"steps": 2})["chain"]
    def as_evidence(step):
        return {"counter": step["counter"], "post_link": step["post_link"],
                "evidence": {"kind": "sev-snp", "report": step["report"],
                             "report_data": report_data_for(bytes.fromhex(step["post_link"])).hex()}}

    ok0, why0 = m.present(tik, sc, exporter, as_evidence(chain[0]))
    print(f"   step 0, fresh link       {'accepted' if ok0 else 'rejected'}: {why0}")
    ok1, why1 = m.present(tik, sc, exporter, as_evidence(chain[1]))
    print(f"   step 1, fresh link       {'accepted' if ok1 else 'rejected'}: {why1}")

    m2 = Mandate(verify, require_anchor=True)
    m2.present(tik, sc, exporter, as_evidence(chain[0]))
    okR, whyR = m2.present(tik, sc, exporter, as_evidence(chain[0]))     # the same Sec 8.4 attack
    print(f"\n   Sec 8.4 attack: resend step 0's Evidence when step 1 is requested")
    print(f"   chained appraisal        {'ACCEPTED' if okR else 'REJECTED'}: {whyR}")

    for i, rd in enumerate(rounds):
        open(f"{OUT}/static-round{i}.bin", "wb").write(base64.b64decode(rd["report"]))
    for st in chain:
        open(f"{OUT}/chain-c{st['counter']}.bin", "wb").write(base64.b64decode(st["report"]))
    json.dump({"guest": blob["instance"], "zone": blob["zone"],
               "constant_binder": {"binder": rounds[0]["binder"],
                                   "report_data_round0": d0.hex(), "report_data_round1": d1.hex(),
                                   "report_data_identical": d0 == d1,
                                   "reports_byte_identical": r0 == r1,
                                   "stale_evidence_accepted": bool(accepted)},
               "chained_binder": {"step0": why0, "step1": why1,
                                  "stale_evidence_accepted": bool(okR), "reason": whyR}},
              open(f"{OUT}/verdict.json", "w"), indent=2)
    print("\nRESULT")
    print(f"   constant binder, stale Evidence at reattestation:  {'accepted' if accepted else 'rejected'}")
    print(f"   chained  binder, stale Evidence at reattestation:  {'accepted' if okR else 'rejected'}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
