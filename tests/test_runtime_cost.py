"""Runtime-attestation cost, pinned on the recorded runs in evidence/runtime-cost-*/ (offline).
See docs/RUNTIME-COST.md."""
import os, glob, json

D = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "evidence", "runtime-cost-*")))[-1]

def test_snp_reports_are_throttled_ten_per_window():
    d = json.load(open(f"{D}/snp-burst.json"))
    assert 7 < d["median_ms"] < 9
    assert [s["index"] for s in d["slow_reports"]] == [10, 20, 30, 40]
    assert all(10000 < s["ms"] < 10500 for s in d["slow_reports"])
    assert d["total_s"] > 40                    # 45 reports took over 40 s: ~1/s sustained

def test_tdx_report_is_microseconds_and_quote_is_tens_of_milliseconds():
    r = json.load(open(f"{D}/tdx-report-latency.json")); q = json.load(open(f"{D}/tdx-quote-burst.json"))
    assert r["tdreport_ms_median"] < 0.05 and r["n"] == 200
    assert 30 < q["median_ms"] < 60 and q["n"] == 100 and q["slow_quotes"] == []
    assert q["quote_bytes"] == 8000

def test_end_to_end_first_link_and_the_throttle_in_the_wild():
    e = json.load(open(f"{D}/e2e-timings.json"))
    assert e["connections"] == 20 and e["links"] == 3
    slow = [i for i, r in enumerate(e["runs"], 1) if max(r["gen_ms_per_link_guest"]) > 1000]
    assert slow == [4, 7, 11, 14, 17]            # the guest's 10th, 20th, ... report
    fast = [r["first_link_total"] for i, r in enumerate(e["runs"], 1) if i not in slow and i > 1]
    assert all(0.2 < t < 0.6 for t in fast)     # first accepted link in 200-600 ms when not throttled

def test_the_liveness_run_already_held_the_maximum():
    p = os.path.join(os.path.dirname(__file__), "..", "evidence", "liveness-20260921T141726Z", "liveness.json")
    d = json.load(open(p))
    assert d["beacon_ms_median"] < 10 and d["beacon_ms_max"] > 10000
