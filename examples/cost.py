#!/usr/bin/env python3
"""What a link costs, measured here, on the real reports this repository ships.

Every number a reader can reproduce from a clone:

  * deriving one link (HKDF over ~80 bytes);
  * appraising one genuine SEV-SNP report -- signature, VCEK -> ASK -> ARK chain, REPORT_DATA --
    cold (the VCEK fetched from AMD's KDS over the network) and warm (cached on disk);
  * one full Mandate.present() step on that report, warm.

Reports come from evidence/reattest-20260922T140735Z/ (GCP, chip 75bbd2bb8dfeeb00).

Usage:  PYTHONPATH=. python3 examples/cost.py
"""
import os, sys, time, json, base64, statistics, shutil
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, intra_link, post_link, report_data_for
from hatls.tee import sevsnp_verifier

EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence", "reattest-20260922T140735Z")

def bench(fn, n):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); fn(); ts.append(time.perf_counter() - t)
    return statistics.median(ts), min(ts), max(ts)

def main():
    rep0 = open(f"{EV}/chain-c0.bin", "rb").read()
    verdict = json.load(open(f"{EV}/verdict.json"))
    print(f"reports: {EV}\n")

    # 1. link derivation
    sc, exp, tik = bytes(48), bytes(32), b"\x30\x59" + bytes(89)
    il = intra_link(sc, tik)
    med, lo, hi = bench(lambda: post_link(exp, il, 1), 20000)
    print(f"post_link (HKDF, one link)          median {med*1e6:7.1f} us   min {lo*1e6:6.1f}   max {hi*1e6:6.1f}   (n=20000)")
    med, lo, hi = bench(lambda: intra_link(sc, tik), 20000)
    print(f"intra_link (first link)             median {med*1e6:7.1f} us   min {lo*1e6:6.1f}   max {hi*1e6:6.1f}   (n=20000)")

    # 2. appraisal of a real report, cold then warm
    ev = {"kind": "sev-snp", "report": base64.b64encode(rep0).decode()}
    # the expected REPORT_DATA is whatever the report carries: this measures verification cost,
    # not a binder check, so read it from the report itself
    expected = rep0[0x50:0x50+64]
    cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hatls", "vcek-cache")   # where hatls/tee.py keeps it
    if os.path.isdir(cache): shutil.rmtree(cache)             # force the cold path once
    verify = sevsnp_verifier(require_chain=True)
    t = time.perf_counter(); ok, anchor = verify(ev, expected); cold = time.perf_counter() - t
    assert ok, "the shipped report must appraise"
    print(f"\nappraise real SEV-SNP report, COLD  {cold*1e3:8.1f} ms   (VCEK + chain fetched from AMD KDS, network)")
    med, lo, hi = bench(lambda: verify(ev, expected), 50)
    print(f"appraise real SEV-SNP report, warm  median {med*1e3:7.1f} ms   min {lo*1e3:6.1f}   max {hi*1e3:6.1f}   (n=50, VCEK cached)")

    # 3. one Mandate.present() step, warm, on the real chain link 0
    # the guest's exporter is not in the evidence (by design), so a real-report present() cannot
    # be replayed here; the mandate's own logic is timed on a mock chip, the chip's signature
    # cost is the warm appraisal above:
    from hatls.tee import MockTEE, mock_verifier
    chip = MockTEE(b"\x11" * 64, b"\x22" * 32); mv = mock_verifier({chip.pub.hex()})
    from hatls.protocol import Attester
    def one_step():
        mm = Mandate(mv, require_anchor=True); att = Attester(chip, tik)
        return mm.present(tik, sc, exp, att.attest(sc, exp))
    ok, why = one_step(); assert ok, why
    med, lo, hi = bench(one_step, 2000)
    print(f"\nMandate.present, full step, mock chip   median {med*1e6:7.1f} us   min {lo*1e6:6.1f}   max {hi*1e6:6.1f}   (n=2000; mock ECDSA P-384 sign+verify, no AMD chain)")
    print(f"\nso: one link is microseconds; the cost that matters is appraising the chip's signature and")
    print(f"chain, which every attestation design pays, and which is {med*1e3:.2f} ms + the warm appraisal above per step.")

if __name__ == "__main__":
    main()
