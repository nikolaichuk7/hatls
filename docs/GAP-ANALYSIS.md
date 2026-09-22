# What SEAT is missing, in the working group's own words, and why nobody built it

Gap analysis, 21 September 2026. Read: the adopted WG document `draft-ietf-seat-use-cases-01`
(attacker model + security goals), the two camp drafts (`early-attestation-07`, `expat-04`), the
hybrid `ritz-seat-facts-00`, `usama-seat-intra-vs-post-04`, and the SEAT charter. This is what
exists, what is absent, and an honest reason for the absence.

## The map

| Security goal / threat (WG use-cases) | Camp 1 intra (early-attestation) | Camp 2 post (expat) | Hybrid (facts) | Ours (measured) |
|---|---|---|---|---|
| 4.1 bind to channel (relay) | transcript | exporter | dual-nonce KEM | both, chained |
| 4.4 freshness (replay) | nonce in binder | nonce | counter-challenge | nonce + chain counter |
| 4.3 bind to machine id (diversion) | partial | partial | — | CHIP_ID from body |
| 3.6 state drift (long-lived/resumed) | conceded, unsolved | conceded | not addressed | continuity chain |
| **3.8.1 re-hosting (stolen key, new TEE)** | **conceded, §8.2** | conceded | **absent** | **mandate: fork detected** |
| 4.8 runtime/continuous attestation | "not achieved" | "not achieved" | absent | write-before-act, measured |

Term counts confirm it: in `ritz-seat-facts` (the hybrid) "continuity" 0, "re-host" 0, "revocation"
0, "mandate" 0, "drift" 0; its "chain" is a certificate chain and its "counter" is a KEM
counter-challenge, not a continuity chain over time.

## The gap is not our opinion — the WG states it

**Re-hosting (use-cases 3.8.1), the mitigation, verbatim:**
> "A deployment that requires **continuity with a particular platform instance** binds authorization
> to that instance, rather than only to an environment class, and provides **a means to reject
> compromised authentication credentials**. Alternatively, the appraisal policy must inform the
> Relying Party whether the authentication key was created in the Target Environment."

The WG names the requirement — continuity-to-instance plus a revocation means — and stops. No
document defines the mechanism. The only alternative it offers is key-provenance
(`reddy-rats-key-binding`), i.e. trusting the hardware's claim.

**Continuous / runtime attestation (use-cases 4.8), verbatim:**
> "to our knowledge, current state-of-the-art systems **do not achieve such a guarantee** ... a
> Time-Of-Check-To-Time-Of-Use (TOCTOU) vulnerability cannot be entirely eliminated."

This is the working group writing, in its adopted document, that the continuity guarantee is an
open problem.

## Why nobody built it (honest reasons, not "they missed it")

1. **It is outside the charter's own framing.** SEAT = Secure Evidence and Attestation *Transport*.
   Chaining identity across time with revocation is lifecycle management, not transport. The two
   camps optimise a single handshake's binding; continuity is a different axis.
2. **It needs a working continuity engine, which participants do not have.** A continuity mandate
   requires hardware-rooted persistent identity, per-identity state at the Relying Party, and a
   revocation path. §4.8 says the state of the art does not do this. Building it is a project, not a
   paragraph.
3. **We arrived with the tool from an adjacent problem.** We built a continuity engine
   (VaultGenome: write-before-act hash chain, key release gated on a fresh unbroken chain,
   fork-detection) to keep a model alive across machine loss. That is the exact shape 3.8.1 asks for.
   Nobody in SEAT built it because nobody came from the "keep a stateful asset alive across hosts"
   problem. We did.

## What we can put on the table that the camps cannot

- **Measured re-hosting detection.** The 3.8.1 attack is caught on hardware in this repository:
  the same identity key presented from a second genuine SEV-SNP instance is declined on its first
  message (`evidence/relay-hw-*`, `evidence/enroll-*`, and on AWS shared tenancy where the silicon
  identifier is masked, `evidence/aws-anchor-*`). That is the mitigation 3.8.1 asks for,
  demonstrated on hardware, which no SEAT document has.
- **Measured cost.** The continuity link is HKDF over ~80 bytes: 2.5 µs (`examples/cost.py`). What
  costs is appraising the chip's report, 1.6 ms warm, and cold whatever AMD's KDS takes that day (0.5 s
  and 7.4 s in two consecutive measurements) — a cost every SEV-SNP design pays and the chain does
  not add to. "Light" is measurable.
- **The malleability rule** that keeps the continuity identity sound (bind to body, not signature).

## Honest limits before we build

- **With enrolment on record**, 3.8.1 is closed by *prevention*: the impostor is refused on its
  first message and the victim is untouched. **Without enrolment** the mandate cannot tell owner
  from thief, so the first presenter is accepted and a later second instance is recorded as
  contention; the incumbent keeps serving and nothing is revoked automatically. Both modes are in
  `examples/attack.py`. (v0.1 said two different things about this ceiling in two documents dated
  the same day — see [AUDIT.md](AUDIT.md) finding 7.)
- **On a platform with no instance anchor the guarantee does not exist**, and HATLS now fails
  closed instead of appearing to work. Measured on our own archive: 15 AWS shared-tenancy VLEK
  reports carry `CHIP_ID = 00…00` across six distinct instances, and `MASK_CHIP_KEY` is *clear* in
  all of them — the platform hides the identifier without setting the flag that says so. Which
  claim should carry instance identity across SEV-SNP, TDX and Nitro is the open question we would
  most like the working groups to settle ([AUDIT.md](AUDIT.md) finding 4).
- Standardising binder + chain + mandate is multi-year. The near-term contribution is a measured
  security-consideration and a reference implementation, not a finished RFC.

## Next, in order, cheapest first

1. Write v0 of the unified binder + continuity + mandate as a runnable spec; debug locally (free).
2. One minimal hardware run proving the core: real attested-TLS on a SEV-SNP guest, continuity chain
   across a re-attestation, and re-hosting caught with the same TIK on two real chips (we already
   hold impersonation captures; this makes it end-to-end and live).
3. Only then scale across regions/clouds to show it survives real Internet latency.

Steps 2-3 cost real cloud money and are Serhii's call on scope; step 1 is free and comes first.

Serhii Nikolaichuk / The Capital Index, Austin, Texas
