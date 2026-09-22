# How much Evidence weighs against the handshake

> `PYTHONPATH=. python3 examples/evidence_size.py` (output in `evidence-size-run.txt`). Artefact
> sizes are from this repository's evidence; the three baselines were measured against live
> servers on 22 September 2026 with `openssl s_client -msg`.

draft-ietf-seat-use-cases-01 4.10 asks that "very large payloads in the initial handshake" be
minimised. Early attestation argues that carrying Evidence in the handshake saves a round trip
(§4.1.2 of intra-vs-post lists the benefit; early-attestation carries it in the Certificate
message); the post-handshake side argues it adds latency (intra-vs-post §4.2.4). Neither gives a
byte count. The bytes:

| artefact | size |
|---|---|
| SEV-SNP attestation report | 1 184 B |
| VCEK leaf (DER) | 1 351 B |
| ASK + ARK (DER) | 1 677 + 1 639 B |
| VLEK leaf (DER, from the AWS guest's certificate table) | 1 319 B |
| TDX quote v4, QE report and PCK chain included | 8 000 B |

and three real TLS 1.3 server first flights, each with a post-quantum hybrid key share
(ServerHello 1 210 B): www.ietf.org, Certificate 3 416 B; www.amazon.com, 4 310 B;
www.microsoft.com, 5 902 B.

The unit that turns bytes into time is the initial congestion window: 10 segments (RFC 6928) of
1 448 B of payload (1 500 MTU, IPv4, TCP timestamps) = 14 480 B. A first flight larger than that
waits one round trip for an ACK before the remainder is sent.

| Evidence in the server Certificate message | bytes | ietf.org | amazon.com | microsoft.com |
|---|---|---|---|---|
| SEV-SNP report only (verifier fetches the chain from AMD's KDS) | 1 184 | 5 segs | 5 | 6 |
| report + VCEK leaf | 2 535 | 6 | 6 | 7 |
| report + VCEK + ASK + ARK (the `SNP_GET_EXT_REPORT` table) | 5 851 | 8 | 9 | **10** |
| report + VLEK leaf (AWS; chain fetched) | 2 503 | 6 | 6 | 7 |
| TDX quote v4 | 8 000 | 9 | 10 | **11 → +1 RTT** |

So, on these measurements:

- **SEV-SNP Evidence never crosses the initial window**, in any form, even carrying the full AMD
  chain against a Microsoft-sized certificate chain — though that case lands exactly on the
  10-segment edge.
- **A TDX quote crosses it** when it meets a long web-PKI chain and a post-quantum key share;
  it sits at the edge with Amazon's chain and one segment below it with IETF's.
- Post-handshake conveyance (expat; the chain in this repository) leaves the first flight at the
  baseline; the same bytes travel later on an established connection, costing bandwidth but not
  the initial-window round trip.
- Client attestation puts the same sizes into a client flight that is otherwise a few hundred
  bytes; none crosses the window there on its own.

Assumptions, so they can be argued with: one record per handshake message with 21 B of record
overhead; a CMW wrapper of about 40 B; the Linux default initial window (larger windows exist);
the IPv4 MSS (IPv6 is 20 B smaller); the `SNP_GET_EXT_REPORT` table counted at its used size, not
the 16 KiB the interface reserves; one TDX quote size, from three identical-length quotes.

What this settles is narrow and useful: the extra-round-trip cost of intra-handshake attestation
is real for TDX-sized Evidence with a long chain and post-quantum key shares, and not observed for
SEV-SNP. Whether one round trip matters is the deployment's question.
