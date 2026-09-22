#!/usr/bin/env python3
"""Time to the first accepted link, end to end, across the Internet, against a real SEV-SNP guest.

The SEAT drafts argue about round trips in words. This measures, from a client on the open
Internet to a confidential VM on GCP, where the time goes:

    connect     TCP SYN -> connected
    handshake   TLS 1.3, to completion (our exporter and session context exist from here)
    request     the probe request goes out, N links come back; the guest reports, per link,
                how long the chip took to produce the report (gen_ms, measured inside the guest)
    appraise    the mandate's full check per link: VCEK chain (cached after the first), signature,
                REPORT_DATA, anchor, chain position
    first link  connect start -> the first link accepted

Repeated over many connections; medians reported with min/max. The cold VCEK fetch from AMD's
KDS is reported separately for the first connection only.

Usage:  PYTHONPATH=. python3 examples/e2e_timing_hw.py <guest-ip> [connections] [links-per-connection]
"""
import os, sys, time, json, statistics, socket, base64
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.protocol import Mandate, report_data_for
from hatls.tee import sevsnp_verifier
from hatls.client import HatlsClient

def as_evidence(step):
    return {"counter": step["counter"], "post_link": step["post_link"],
            "evidence": {"kind": "sev-snp", "report": step["report"],
                         "report_data": report_data_for(bytes.fromhex(step["post_link"])).hex()}}

def one(ip, verify, steps):
    t = {}
    t0 = time.perf_counter()
    sock = socket.create_connection((ip, 8443), timeout=60); t["connect"] = time.perf_counter() - t0
    sock.close()
    t1 = time.perf_counter()
    with HatlsClient(ip, 8443) as c:                      # includes its own TCP connect + TLS handshake
        t["connect+handshake"] = time.perf_counter() - t1
        exporter, sc, tik = c.exporter, c.session_context, c.peer_identity_key
        t2 = time.perf_counter()
        blob = c.request({"steps": steps}); t["request->response"] = time.perf_counter() - t2
    chain = blob["chain"]; t["gen_ms_per_link_guest"] = [s.get("gen_ms") for s in chain]
    m = Mandate(verify, require_anchor=True); appr = []
    for s in chain:
        t3 = time.perf_counter(); ok, why = m.present(tik, sc, exporter, as_evidence(s)); appr.append(time.perf_counter() - t3)
        assert ok, why
    t["appraise_per_link"] = appr
    t["first_link_total"] = t1 - t0 + t["connect+handshake"] + t["request->response"] + appr[0]
    t["bytes_response"] = len(json.dumps(blob))
    return t

def ms(x): return f"{x*1000:7.1f} ms"

def main(ip, n=20, steps=3):
    verify = sevsnp_verifier(require_chain=True)
    print(f"guest {ip}:8443, {n} connections x {steps} links, client on the open Internet\n")
    runs = [one(ip, verify, steps) for _ in range(n)]
    first = runs[0]
    print(f"connection 1 (cold: VCEK + chain fetched from AMD KDS during the first appraisal):")
    print(f"   appraise link 0            {ms(first['appraise_per_link'][0])}")
    warm = runs[1:]
    def med(key, idx=None):
        vals = [(r[key][idx] if idx is not None else r[key]) for r in warm]
        return statistics.median(vals), min(vals), max(vals)
    print(f"\nconnections 2..{n} (warm), median [min .. max]:")
    for key, label in (("connect", "TCP connect"), ("connect+handshake", "TCP + TLS 1.3 handshake"),
                       ("request->response", f"request -> {steps} links back")):
        a, b, c = med(key); print(f"   {label:34s} {ms(a)}  [{ms(b).strip()} .. {ms(c).strip()}]")
    g = [x for r in warm for x in r["gen_ms_per_link_guest"] if x is not None]
    if g: print(f"   {'chip report generation (in guest)':34s} {statistics.median(g):7.1f} ms  [{min(g):.1f} ms .. {max(g):.1f} ms]   n={len(g)}")
    a, b, c = med("appraise_per_link", 0); print(f"   {'appraise one link (warm)':34s} {ms(a)}  [{ms(b).strip()} .. {ms(c).strip()}]")
    a, b, c = med("first_link_total"); print(f"   {'FIRST ACCEPTED LINK, from SYN':34s} {ms(a)}  [{ms(b).strip()} .. {ms(c).strip()}]")
    a, b, c = med("bytes_response"); print(f"   {'response bytes (JSON, base64)':34s} {a:7.0f}")
    out = {"guest": ip, "connections": n, "links": steps, "runs": runs}
    OUT = f"evidence/e2e-timing-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"; os.makedirs(OUT, exist_ok=True)
    json.dump(out, open(f"{OUT}/timings.json", "w"), indent=1); print(f"\nevidence -> {OUT}/timings.json")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 20, int(sys.argv[3]) if len(sys.argv) > 3 else 3))
