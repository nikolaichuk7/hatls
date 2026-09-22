#!/usr/bin/env python3
"""How much Evidence weighs against the TLS 1.3 handshake, in real bytes.

draft-ietf-seat-use-cases-01 4.10: "very large payloads in the initial handshake should be
minimized." The intra-handshake camp says attestation in the handshake saves a round trip
(early-attestation 4.1.2); the post-handshake camp says it adds latency (intra-vs-post 4.2.4).
Neither draft gives a byte count. These are the artefacts this repository ships, measured:

  SEV-SNP report                 1184 B      (evidence/, any of the 87)
  VCEK leaf, DER                 1351 B      (hatls/vcek-cache/)
  ASK + ARK, DER          1677 + 1639 B      (hatls/vcek-cache/Milan-vcek-chain.pem)
  VLEK leaf, DER                 1319 B      (the AWS guest's certificate table)
  TDX quote v4                   8000 B      (evidence/tdx-quotes-20260911/; includes the QE
                                              report and the PCK certificate chain, 4165 B)

and real baselines, TLS 1.3 server first flights measured on 22 Sep 2026 (openssl s_client -msg):
www.ietf.org       ServerHello 1210 B (an X25519MLKEM768 key share), EncryptedExtensions 10,
                   Certificate 3416, CertificateVerify 79, Finished 52
www.amazon.com     ServerHello 1210, Certificate 4310
www.microsoft.com  ServerHello 1210, Certificate 5902

The unit that decides whether bytes cost a round trip is the initial congestion window:
10 segments (RFC 6928) of 1448 B of payload each (1500 MTU, IPv4, TCP timestamps) = 14480 B.
A first flight larger than that waits one RTT for an ACK before the rest goes out.

Usage:  PYTHONPATH=. python3 examples/evidence_size.py
"""
MSS, INITCWND = 1448, 10
BUDGET = MSS * INITCWND
CMW = 40                                   # CBOR CMW wrapping, order of magnitude
REC = 5 + 16                               # TLS record header + AEAD tag, per record (one record assumed per message)

baselines = {"www.ietf.org": 3416, "www.amazon.com": 4310, "www.microsoft.com": 5902}   # Certificate message
def flight_base(cert): return 1210 + 10 + cert + 79 + 52 + REC * 5

evidence = {
    "SEV-SNP report only (verifier fetches VCEK+chain from AMD KDS)":       1184,
    "SEV-SNP report + VCEK leaf":                                          1184 + 1351,
    "SEV-SNP report + VCEK + ASK + ARK (SNP_GET_EXT_REPORT table)":        1184 + 1351 + 1677 + 1639,
    "SEV-SNP report + VLEK leaf (AWS; chain fetched)":                     1184 + 1319,
    "TDX quote v4 (QE report + PCK chain included)":                       8000,
}

def segs(n): return -(-n // MSS)

def main():
    print(f"initial congestion window: {INITCWND} x {MSS} B = {BUDGET} B\n")
    for site, cert in baselines.items():
        bt = flight_base(cert)
        print(f"baseline {site:18s} server flight {bt:5d} B = {segs(bt)} segments  (PQ hybrid ServerHello, Certificate {cert} B)")
    print()
    hdr = f"{'Evidence in the server Certificate message (early attestation)':64s} {'bytes':>6s}"
    for site in baselines: hdr += f" {site.replace('www.',''):>16s}"
    print(hdr); print(" " * 71 + "".join(f"{'flight/segs':>17s}" for _ in baselines))
    for k, v in evidence.items():
        row = f"  {k:62s} {v:6d}"
        for site, cert in baselines.items():
            flight = flight_base(cert) + v + CMW
            row += f" {flight:6d}/{segs(flight):<2d}{'+1RTT' if flight > BUDGET else '     '}"
        print(row)
    print()
    print("Post-handshake (expat, or the chain here): the first flight is the baseline; the same bytes travel")
    print("after the handshake, on an established connection, where they cost bandwidth but not the")
    print("initial-window round trip.")
    print()
    print("Client attestation (client Certificate carries Evidence): the client's second flight is otherwise")
    print("a few hundred bytes, so none of these Evidence sizes crosses the window there on its own.")

if __name__ == "__main__":
    main()
