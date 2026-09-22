# What runtime attestation costs, measured: SEV-SNP against TDX, and end to end

> Evidence: `evidence/runtime-cost-20260922T153300Z/` (raw per-call timings). Client for the
> end-to-end run: `examples/e2e_timing_hw.py`. Both guests were on GCP and were deleted after.

draft-ietf-seat-use-cases-01 §4.8 wants Evidence "periodically or on-demand during the lifetime
of the connection" and §4.10 wants the cost practical. The drafts do not say what a fresh report
costs on real silicon, or how often one can be had. Measured, 22 September 2026:

## One piece of evidence, on the chip

| | SEV-SNP (GCP `n2d-standard-2`, Milan, chip `75bbd2bb…`) | Intel TDX (GCP `c3-standard-4`, kernel 7.0.0-1011-gcp) |
|---|---|---|
| local evidence | — | **TDREPORT: 6 µs** median, 35 µs max (n=200) — a `TDCALL` into the TDX module, MAC-bound to that module, **not remotely verifiable** |
| remotely verifiable evidence | **report: 7.7 ms** median (n=45); 7.8 ms across 57 links in the end-to-end run | **quote: 38.9 ms** median, 41.1 ms max (n=100) — the TDREPORT goes to the host's Quote Generation Service and comes back signed by the QE (`configfs-tsm`) |
| sustained cadence, back to back | **throttled: 10 reports per ~10.3 s.** Reports 10, 20, 30, 40 each waited 10.23–10.26 s; 45 reports took 41.3 s. ≈ **1 report / s** sustained | **no throttle observed**: 100 quotes in 3.9 s, none slower than 41 ms; ≈ 25 quotes / s |

The SEV-SNP throttle is the host's. The Linux guest driver documents it (`arch/x86/coco/sev/core.c`):
*"The host may return SNP_GUEST_VMM_ERR_BUSY if the request has been throttled. Retry in the
driver"* — with `SNP_REQ_RETRY_DELAY = 2*HZ` and a 60-second ceiling. A bucket of ten per ten
seconds, polled every two, is exactly the 10.2-second stall observed on every tenth request. What
the bucket's parameters are on other hosts, or on GCP tomorrow, is the host's decision; this is
what it was.

## End to end, across the Internet

A client in Austin to the SEV-SNP guest in us-central1, 20 connections of 3 links, medians of
connections 2–20 (`e2e-run.txt`):

| phase | median | min .. max |
|---|---|---|
| TCP connect | 40.9 ms | 35.4 .. 126.9 |
| TCP + TLS 1.3 handshake | 89.1 ms | 82.6 .. 191.8 |
| request → 3 links back (3 chip reports + network) | 109.1 ms | 105.0 .. **10 349.6** |
| appraise one link, warm VCEK (signature, AMD chain, `REPORT_DATA`, anchor, position) | 5.5 ms | 2.2 .. 8.4 |
| **first accepted link, from SYN** | **318 ms** | 235.7 .. **10 483** |

Five of the twenty connections met the throttle: each one had exactly one link — the guest's
10th, 20th, 30th, 40th, 50th report of the session — take 10.2 s, and so the whole connection.
The response carrying three links, JSON and base64, was 5 199 bytes.

The first connection's appraisal took 8.3 ms, not seconds: the chip was the same one as the
morning's guests and its VCEK was already cached, so the cold fetch from AMD's KDS was not
exercised here. That cost is measured separately in `examples/cost.py` (0.5 s and 7.4 s in two
consecutive attempts; KDS latency varies by an order of magnitude).

## What this corrects in this repository's own claims

`tools/liveness_probe.py` was run on 21 September (`evidence/liveness-20260921T141726Z/`) and
reported a beacon of **7.96 ms median** — and, in the same file, **10 237 ms max**. The maximum
was the throttle, already in our data, and every document quoted the median as though it were a
rate ("up to ~125/sec"). It is not. On this host, 7.96 ms is the latency of a report inside the
bucket; the sustained cadence is about one per second. Wherever this repository says the beacon
bounds the *resolution* of detection, read: bounded by the throttle, ~1 s here, not by 8 ms.
The README, threat model, goals statement and audit are corrected in the same commit as this file.

## What this means for the working group's question

- On SEV-SNP as hosted today, "periodic attestation" finer than once a second is not available
  to a guest, whatever the transport; a design that budgets 100 reattestations a second would
  stall at the eleventh. Nothing in the SEAT drafts assumes a rate, and now there is one to assume.
- On TDX the remotely verifiable quote is five times slower per unit than an SNP report but not
  throttled in the run; the local TDREPORT is three orders of magnitude faster than either and
  proves nothing to a remote party by itself.
- A chain of links (this repository) spends one report per link, so on SEV-SNP it inherits the
  one-per-second sustained budget; the ordering guarantee does not depend on cadence.
