# One protocol instead of two camps: intra + post + mandate, measured where it can be

Design discussion, 21 September 2026. Idea is Serhii's: stop treating "inside the handshake" vs
"after the handshake" as a contest; chain them so no substitution passes at any stage, and add a
mandate (key release / revocation, the continuity work from the product side) to close what crypto
alone cannot. This note tests the buildable parts on real data and states plainly where the idea
meets a hard limit.

Empirical support: `continuity_binder.py` (real 11 Sep SEV-SNP relay run), plus the earlier
`REPORT.md` and `SIGNATURE-MALLEABILITY.md`.

## The timeline, and the four windows where substitution can happen

    t0  ClientHello / ServerHello      fresh ephemeral keys; TRANSCRIPT exists (public)
    t1  Certificate + intra Evidence   Camp 1 binds here, to the transcript
    t2  Finished -> handshake complete  EXPORTER (shared secret) now exists
    t3  ... application data ...        TEE state can drift
    t4  re-attestation (post)          Camp 2 binds here, to the exporter

- Window A, at t1: the intra binder commits to the transcript + public key. An adversary that
  holds the server's key (stolen by side-channel, then run in its own TEE) is a genuine endpoint;
  it passes. Measured: our relay run, "Camp 1 key binder accepts = True". This is -07 Section 8.2,
  which -07 concedes.
- Window B, t2->t4: attestation goes stale; the RP is not told. -07 Section 8.6 concedes this.
- Window C, at t4: -07 Section 8.4 concedes the binder does not change over the connection, so an
  old post-Evidence can be replayed into a re-attestation.
- Window D, any time: signature malleability lets a middlebox mint a second valid-looking signed
  report of the same body (our SIGNATURE-MALLEABILITY finding), which matters to any log/ledger
  that de-duplicates by signature.

No single binder covers all four, because the two anchors do not co-exist: the transcript is
public and early, the exporter is secret and late (Fossati Appendix B says this outright).

## The linking element, and what it actually catches (measured)

Define a continuity link computed the instant the handshake finishes and again at each
re-attestation:

    intra_link = HKDF(transcript_checkpoint, server_key)          # Camp 1 value, available at t1
    link_n     = HKDF(exporter_n, intra_link || counter_n)        # Camp 2 secret + chain + order

On the real 11 Sep run:

    HONEST : Camp1 accepts, Camp2 accepts, continuity links MATCH.
    RELAY  : Camp1 alone accepts (key+transcript genuine) -> intra-only is fooled;
             Camp2 rejects, and the continuity link DIFFERS -> caught at the first post link,
             without waiting for a full re-attestation.
    counter: link#1 != link#2 for the same session, so a replayed old link is detected (Window C).

So the chain closes Windows B and C by construction (freshness + order), and it makes Window A
*detectable at the first post link* rather than invisible. The linking step is HKDF over ~80 bytes:
microseconds, no extra round trip. Window D is closed separately by binding identity to the report
body, not the signature (our malleability rule).

## The hard limit, stated honestly, and where the mandate earns its place

Window A is not *prevented* by any binder, chain included: an adversary with the genuine key on a
genuine TEE is cryptographically indistinguishable from the real server at t1. The chain makes the
two diverge at the first *post* link (different exporter), but for one message at t1 the intra-only
view is fooled. Two things, and only two, address the key itself:

1. Key provenance -- Evidence that asserts the key was generated in this TEE and is
   non-extractable (`I-D.reddy-rats-key-binding`). This is trust in the hardware's claim.
2. The mandate -- and this is the part that is ours to contribute. A stolen key used in a second
   TEE produces a SECOND continuity stream under the same identity. A mandate that releases/keeps
   a key alive only while ONE continuous, ordered, fresh chain exists for that identity detects the
   fork and revokes. We measured exactly this shape in the product's failover-negatives drill: two
   endpoints presenting one sealed identity -> the second is declined.

So the honest guarantee of "intra + post + mandate" is not "no substitution". It is
**"no substitution without detection and revocation"**: crypto stops relay and replay outright
(Windows B, C, D), and the mandate turns the one residual case (Window A, key theft) from silent
success into a detected fork that costs the attacker the key. That is a real, defensible, and
new combination -- and it is the honest ceiling, not "perfect security".

## Why it can be light

The fear is that a chain needs state and Camp 1's whole selling point is that it needs none. Two
measurements push back:

- The linking step is arithmetic (HKDF over 80 bytes), microseconds. It adds nothing to the hot
  path; the expensive part is appraising the Evidence, which every design pays anyway.
- The state an RP must keep is small: the last link and a counter per live identity (tens of
  bytes). Not a database -- a register.

So the weight is one HKDF at t2, one per re-attestation, and ~40 bytes of memory per connection.
The mandate's cost (our measured continuity commit, 0.26-1.42 s) sits inside the key-release phase,
dominated by appraisal (6.8-14.4 s), i.e. off the latency-critical path.

## Is this new?

The hybrid direction is in the air (`I-D.ritz-seat-facts` mixes intra and post). What is not done
by anyone: a single binder chain that (a) carries the intra transcript AND the post exporter with
an order counter, and (b) is governed by a mandate that revokes on chain-fork, backed by a hardware
measurement of the fork case. Camp 1 has no post link; Camp 2 has no continuity/mandate; neither
binds the malleability rule. The pieces exist separately; the synthesis, and the honest ceiling it
reaches, do not.

## Risks and what to test next

- Standardising a new binder + chain + mandate in TLS is a large, multi-year effort; the "light"
  claim must survive a real implementation, not just the arithmetic.
- The mandate needs a canonical identity to chain on. On SEV-SNP that is CHIP_ID/REPORT_ID from the
  body (malleability-safe); on masked VLEK (AWS shared) CHIP_ID is zero, so the mandate has weaker
  ground there -- worth measuring what identity survives masking.
- Window A detection latency = one post link. Measure it end to end, not just the HKDF.
- psk_ke resumption (our open E3) interacts with the chain; needs a stack that will produce it.

Serhii Nikolaichuk / The Capital Index, Austin, Texas
