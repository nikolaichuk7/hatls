> **Read [AUDIT.md](AUDIT.md) first.** The runs at the top are the current ones (22 Sep 2026:
> reattestation freshness; 21 Sep 2026: identity anchored on the instance claim). **Everything after it is a historical record of earlier runs,**
> kept unedited because evidence should not be rewritten after the fact.
>
> Those earlier runs were produced by v0.1, whose client read the TLS exporter and the identity key
> out of the peer's own message and whose enrolment never bound the key to the chip. What still
> stands in them: the reports are genuine, the chips and signatures are real, and re-hosting across
> two distinct chips was genuinely detected. What does not: any relay resistance they seem to
> imply, because the client of the day could not have detected a relay; and the revocation of guest
> A once guest B appeared, which is now understood as an attack on the victim, not a success.

# Run of 22 September 2026, 16:05 UTC — a TD gives itself an instance identity

Two GCP `c3-standard-4` TDX guests from one Ubuntu 24.04 image (kernel 7.0.0-1011-gcp), both
deleted after. Evidence: `evidence/tdx-rtmr-20260922T160500Z/` — a TDREPORT before and after,
per guest, and the nonce each drew (kept only to verify the arithmetic).

```
MRTD                          identical (same image)
RTMR3 before                  0 in both
extend rtmr3:sha384 with 48 random bytes, once, in each guest
RTMR3 after                   372d9c85... (a)   d3345726... (b)   distinct
SHA-384(0 || nonce) == after  True in both     (TDG.MR.RTMR.EXTEND, as documented)
RTMR0..2, MRTD, MROWNER...    unchanged
```

`docs/INSTANCE-IDENTITY.md` says what this does and does not give; `tdx_anchor` in
`hatls/tee.py` reads it and fails closed on a zero RTMR3.

# Runs of 22 September 2026, 15:26–15:33 UTC — what a report costs, and how many you may have

`examples/e2e_timing_hw.py` against a GCP SEV-SNP guest (`hatls-e2e`, us-central1-c, chip
`75bbd2bb8dfeeb00`), and two in-guest bursts, one on that guest and one on a GCP TDX guest
(`tdx-lat`, c3-standard-4, us-central1-a). Both deleted after. Evidence:
`evidence/runtime-cost-20260922T153300Z/`. Full write-up: `docs/RUNTIME-COST.md`.

```
SEV-SNP report, in guest        7.7 ms median (n=45)   every 10th: 10.23-10.26 s  (host throttle,
                                                        ~10 per 10 s; the driver retries every 2 s)
TDX TDREPORT, in guest          6 us median (n=200)     local, MAC-bound, not remotely verifiable
TDX quote via host QGS          38.9 ms median (n=100)  no throttle in 100; 8000 B each

end to end, Austin -> us-central1, 20 connections x 3 links, medians of 2..20:
  TCP connect 40.9 ms | TCP+TLS 1.3 89.1 ms | request -> 3 links 109.1 ms | appraise (warm) 5.5 ms
  FIRST ACCEPTED LINK from SYN: 318 ms   (5 of 20 connections hit the throttle: 10.4-10.5 s)
```

This run also corrected a claim of ours: the 21 September liveness file already recorded a
10 237 ms maximum next to its 7.96 ms median, and the median had been presented as a rate.

# Run of 22 September 2026, 14:07 UTC — reattestation freshness, with the draft's own binder

`examples/reattest_freshness_hw.py`, one GCP `n2d-standard-2` SEV-SNP guest (`hatls-84b`,
us-central1-c, chip `75bbd2bb8dfeeb00`), deleted after the run. Evidence:
`evidence/reattest-20260922T140735Z/` — the four 1184-byte reports, the ClientHello and
ServerHello as recorded on the verifier's side, `run.txt`, `verdict.json`.

draft-fossati-seat-early-attestation-07 Section 8.4 says an attester "could resend Evidence
generated earlier in the connection in response to a later reattestation request, since the
binder still matches and the Relying Party has no way to distinguish it from fresh Evidence",
and that "the mechanism will be defined in future revisions". This run measures both halves.

**A. The draft's binder, exactly as Section 5.1.1 defines it.** Both ends run TLS 1.3 over
memory BIOs and record the wire, so each can compute `Hash(ClientHello..ServerHello)` from its
own view; the binder is `HKDF-Expand-Label` in the `tls13 ` label space with the suite's hash
(`TLS_AES_256_GCM_SHA384`, so SHA-384 and a 48-byte binder), over that transcript hash and the
server's SubjectPublicKeyInfo. The verifier derives it from its own recording and the
certificate the handshake proved possession of (Section 5.1.2), and compares it to what the
chip signed. `hatls/transcript.py` is checked byte for byte against the RFC 8448 trace.

```
suite / hash                TLS_AES_256_GCM_SHA384 / sha384
ClientHello, ServerHello    224 + 122 bytes, seen on OUR side of the wire
transcript sha256 agrees    True
binder, ours == guest's     True   (48 bytes, 37ea07e49dc00ca9b2cff274...)
round 0 authentic + binds   True   (VCEK -> ASK -> ARK; REPORT_DATA == our binder)
round 1 authentic + binds   True
REPORT_DATA identical       True
whole report identical      False   (signatures are randomised)
fields equal in both        MEASUREMENT, CHIP_ID, REPORT_ID

Sec 8.4 attack: resend round 0's Evidence when round 1 is requested
Sec 5.1.2 appraisal         ACCEPTED
```

Two genuine, separately signed reports from one connection carry byte-identical `REPORT_DATA`.
A Relying Party appraising the binder has nothing to tell them apart by. Section 8.4, measured.

After the run the binder was re-derived a third way — `cryptography`'s `HKDFExpand` over the
saved `client-hello.bin`, `server-hello.bin` and the guest certificate's SPKI — and reproduces
`37ea07e4…`; it sits at offset `0x50` of both saved reports, zero-padded to 64 bytes.

**B. The chained binder.** Same guest, same silicon, `post_link = HKDF(exporter, prev_link ‖ counter)`:

```
step 0, fresh link          accepted: accepted; continuity intact
step 1, fresh link          accepted: accepted; continuity intact
Sec 8.4 attack: resend step 0's Evidence when step 1 is requested
chained appraisal           REJECTED: counter did not advance by one (replay or reorder)
```

A chained link is not merely fresh, it is **positioned**: link *n* cannot stand in for link
*n+1*. An exchange-specific binder of the kind Section 8.4 sketches would give freshness but
would still need ordering added on top, because two independent fresh binders say nothing
about which came first. The same property is proved in `formal/hatls-chain.pv`, and the prover
finds the Section 8.4 trace in `formal/hatls-constant-binder.pv`.

**Scope.** The binder is placed raw in `REPORT_DATA`, left-aligned and zero-padded: the draft
fixes no SEV-SNP encoding, this is the most literal reading of "as a nonce value", and any
deterministic encoding gives the same result. HelloRetryRequest handshakes are refused, not
modelled. This is not an argument against early attestation: the chain sits on top of either
transport.

**Earlier the same day, 13:34 UTC** (`evidence/reattest-20260922T133416Z/`): the same
experiment with a constant binder derived from the session exporter rather than the transcript
— an analogue, labelled as such — gave the same two verdicts on guest `hatls-84`, same chip.
That run also found the guest probe had been unable to answer any connection since v0.2.0
(a swallowed assignment; see `tests/test_guest_probe_agrees.py`). Kept as the record of how the
result was reached.

The relay defence was re-run against the rebuilt probe (`evidence/relay-hw-20260922T140812Z/`):
enrolled, two links accepted direct, relay holding the guest's real stolen key declined on link
0. `hatls-84b` reports the same `CHIP_ID` as the morning's `hatls-84` and a different
`REPORT_ID` (`7d8866f8…` vs `cea42ce7…`): the same silicon, a new instance.

# Run of 21 September 2026, 20:47 UTC — AWS: the instance anchor where the silicon anchor is gone

`examples/aws_anchor_run.py`, two AWS EC2 SEV-SNP instances in **us-east-2** and **eu-west-1**,
both terminated after the run. Evidence: `evidence/aws-anchor-20260921T204747Z/`.

The archive said `CHIP_ID` is zeroed on AWS shared tenancy, that the VLEK signing key is shared
region-wide, and that `REPORT_ID` is distinct anyway. That was an argument from stored bytes. This
is machines launched now.

```
us-east-2a  VLEK   CHIP_ID all zero: True   MASK_CHIP_KEY flag: False
            instance (REPORT_ID) 05496ec336fcdb23   place ABSENT
eu-west-1a  VLEK   CHIP_ID all zero: True   MASK_CHIP_KEY flag: False
            instance (REPORT_ID) 4bd0091ce0c0b237   place ABSENT

enrol   us-east-2a                        : True (enrolled)
present eu-west-1a, same key, other instance : False
   -> rejected: key presented from an instance it was not enrolled on
present us-east-2a, the enrolled one      : True (accepted; continuity intact)
```

The refusal is by the anchor, not by unverifiable evidence: the mandate log shows
`rejected-impostor` naming the enrolled instance and the presented one.

## Two things this run found that the archive could not

**The verifier could not appraise AWS at all.** It refused VLEK-signed reports outright, with a
correct reason -- AMD does not publish that leaf by `CHIP_ID` -- and the consequence was that a
platform whose anchor works perfectly was simply unusable. The leaf lives in the host certificate
table the guest reads with `SNP_GET_EXT_REPORT`; evidence now carries it, and the chain validates
through AMD's **vlek** chain rather than the vcek one. Table entry `a8074bc2`, leaf 1319 bytes.

**`SNP_GET_EXT_REPORT` fails with a bare EINVAL** unless `certs_len` is page-aligned and no larger
than the kernel's `SEV_FW_BLOB_MAX_SIZE` of 16384. Measured on Amazon Linux 2023, kernel
6.1.186-228.376. Nothing in the error says so.

## What this run does and does not show

It shows the instance anchor doing its job on live shared-tenancy hardware where the silicon claim
is absent and the signing key is shared: two machines told apart, one enrolled, the other refused
on its first message, the owner still served.

It does not show the TLS binding. AWS SEV-SNP guests here have no inbound network -- no security
group, no key pair -- so they report through the serial console, and **the exporter and session
context are supplied to the guest rather than derived from a live handshake**. The relay defence
is what the GCP runs prove.

---

# Run of 21 September 2026, 20:02 UTC — two mandates reconciled through the attester

`examples/federation_hw.py`, one SEV-SNP guest in `europe-west4-b`, instance `966b8530389a69d1`,
deleted after the run. Evidence: `evidence/federation-hw-20260921T200251Z/`.

Preventing two mandates from diverging needs consensus. Detecting it needs only that their claims
meet somewhere, and in Certificate Transparency that meeting -- gossip -- is the unsolved part.
Here both mandates already trust the same TEE, so one report carries both their heads at once.

```
mandate A (799f6f0b): enrolled       mandate B (fc4f2543): enrolled
both anchored on instance 966b8530389a69d1

bundle bound by the guest: [(799f6f0b, size 1, bbb3bd1a8a75), (fc4f2543, size 1, bbb3bd1a8a75)]
commitment: 8beada28e07e35979a2b45a1

mandate A accepts: True      mandate B accepts: True

REPORT_DATA signed by AMD  : 39fc11d7f3dcd2783546cf86d15d9d5e
rebuilt from link + bundle : 39fc11d7f3dcd2783546cf86d15d9d5e
a tampered bundle would match: False

after A rewrites its log -> diverged=True
  same size, different root: the peer signed two histories
```

Re-checked offline from the archived files alone. The two roots coincide here only because both
logs held the same single decision at that moment; the mandates are distinguished by the key each
signs with, which is what the bundle names.

What this run shows: two independent mandates, neither trusting the other and neither online for
the other, whose claims are pinned together inside one AMD-signed report; and a mandate that
rewrites afterwards being caught with that report alone.

What it does not show: prevention. Two mandates can still admit different instances. What is bought
is that doing so leaves a mark the party who did it cannot remove.

---

# Run of 21 September 2026, 19:54 UTC — the chip as a witness to the mandate's ledger

`examples/witness_hw.py`, one SEV-SNP guest in `europe-west4-b`, instance `a41b810b4e16c826`,
deleted after the run. Evidence: `evidence/witness-hw-20260921T195447Z/`.

A log makes the mandate's decisions non-repudiable, but the head of that log is still the mandate's
own word: it can sign two well-formed histories. Here the verifier hands the attester its current
ledger head, the guest binds it into `REPORT_DATA`, and AMD's key signs across it.

```
ledger size 1, head 0ec05af4c852973dca6fb5fa
  accepted; continuity intact
  receipt verifies against the mandate's key: True

what an auditor can check, holding only the report:
  REPORT_DATA the chip signed : 808822478097306feedd69121a46fa3d
  recomputed from link + head : 808822478097306feedd69121a46fa3d
  the claimed head is the one AMD signed across : True
  any other head would also match               : False

and afterwards:
  the mandate still accounts for the witnessed head : True
  after rewriting its log, it accounts for it       : False
```

Re-checked offline from the archived files alone: the report is a genuine 1184-byte SEV-SNP report,
its `REPORT_DATA` equals `SHA-512("HATLS-continuity-v1" || post_link || head)` and **not** the v0
binder, and the receipt verifies against the mandate's public key with no access to the mandate.

The point is the ownership of the signing key. The mandate cannot mint a report saying it claimed a
different ledger state, because the key is the chip's. The party being audited cannot forge its own
witness.

What this does not do: it does not prevent equivocation, it makes it evidential. It also says
nothing about a mandate that never issues a head, and nothing yet about how two mandates serving
one identity stay consistent.

---

# Run of 21 September 2026, 19:42 UTC — identity anchored on the instance claim

Two AMD SEV-SNP confidential VMs on GCP sharing one TLS identity key. Both deleted afterwards;
`gcloud compute instances list` returns nothing. Evidence:
`evidence/transfer-hw-20260921T194224Z/`, `evidence/enroll-20260921T194237Z/`,
`evidence/relay-hw-20260921T194244Z/` — 13 genuine 1184-byte reports.

This run is the first on the corrected anchor. The two claims are visibly different values:

| guest | zone | **instance** (`REPORT_ID`) | place (`CHIP_ID`) |
|---|---|---|---|
| A | `europe-west4-b` | `d75823da742057fb` | `48d22d19657beb39` |
| B | `europe-west4-a` | `1f59783aa5b0be8a` | `a775177c63f1d342` |

The mandate anchors on the instance. The chip is recorded as place and is not identity — which is
what lets the same design work on a platform whose `CHIP_ID` is masked away, and what lets two
guests on one socket be told apart at all.

## 1. Owner-authorised transfer, end to end on real silicon

`examples/transfer_hw.py`. The sequence the mandate requires, with nothing simulated:

```
1. enrolled on instance d75823da7420, owner key named as transfer authority
2. instance 1f59783aa5b0 presents the same identity key
     -> rejected: key presented from an instance it was not enrolled on
     -> and WITNESSED: the evidence was valid, so the mandate now knows that instance exists
3. the owner issues a grant: from d75823da7420 -> to 1f59783aa5b0, single use, 300s window
     -> accepted: transferred to the authorised instance
4. instance 1f59783aa5b0 : accepted; continuity intact
   instance d75823da7420 : rejected, it no longer holds the identity
   the same grant again   : grant has already been used
```

A dispute between two genuine instances is settled by the party the identity nominated, not by the
mandate guessing. This also gives a dead machine a way back: step 2 is what recovery looks like,
and the grant is the owner saying it was meant.

## 2. Enrolment prevention on the instance anchor

`examples/enroll_run.py`. Guest B, same key, different instance, refused on its FIRST message; the
victim keeps serving. Identical to the earlier run in outcome, but now the refusal is on the claim
that actually identifies the Target Environment.

## 3. Relay with a real stolen key

`examples/relay_hw.py`. Unchanged and still holds: direct accepted, relayed rejected at counter 0,
guest-side exporter `fa1b273292e215fc` against client-side `3c2f6cd314c74172`.

## What this run does and does not show

It shows, on live silicon: identity anchored on the instance claim, an impostor refused on its
first message, an owner-authorised transfer with its replay refused, and relay resistance against a
genuinely stolen key.

It does not show: a masked-`CHIP_ID` platform, because both GCP guests expose one — the AWS case is
established from the archived corpus and from the specification, not from this run; TDX or Nitro;
a migration agent, absent from every report we hold; or the physical-insider case.

---

# Run of 21 September 2026, corrected code (`audit/p0-hardening`)

Two AMD SEV-SNP confidential VMs on Google Cloud, launched with the **same** TLS identity key so
that the second models re-hosting. Both deleted afterwards; `gcloud compute instances list` returns
nothing. Evidence: `evidence/relay-hw-20260921T183741Z/`, `evidence/enroll-20260921T183801Z/`,
`evidence/20260921T183842Z/` — 16 genuine 1184-byte reports across two distinct chips.

| | |
|---|---|
| guest A | `europe-west4-b`, chip `dd92cae137e7f2cf` |
| guest B | `europe-west4-a`, chip `15f90cb088627a60` |
| Evidence | VCEK-signed, fetched from AMD KDS, path-validated to the ARK, `POLICY.DEBUG` refused |

## 1. Relay, with a real stolen key, against a real confidential VM

`examples/relay_hw.py`. A relay on the operator machine holds guest A's genuine TLS key,
terminates our TLS with it, opens its own session to the VM, and forwards the guest's genuine
VCEK-signed reports **untouched**. Nothing is forged; AMD's signature covers every byte it passes.

```
direct   counter 0,1 : accepted
relayed  counter 0   : REJECTED -- link does not chain
guest-side exporter c903cd6742fd8d82  !=  client-side 1f7debc3f3174911
```

This is the claim v0.1 could not have supported: its client read the exporter out of the peer's
message, which a relay forwards unchanged. The defence works because the verifier now derives that
value from its own side of the connection ([AUDIT.md](AUDIT.md) finding 1).

## 2. Enrolment prevention — the impostor is stopped on its first message

`examples/enroll_run.py`. Guest A enrols with a real PKCS#10 CSR carrying its identity key,
self-signed as proof of possession, over a nonce the mandate issued.

```
enrol guest A (chip dd92cae137e7)            : enrolled
guest B, same key, chip 15f90cb08862, msg #0 : REJECTED -- not the instance it was enrolled on
guest A afterwards                           : ACCEPTED -- the victim is untouched
```

The last line is the difference from v0.1, which revoked guest A at this point. An impostor
presenting a stolen key can no longer destroy the identity it is impersonating
([AUDIT.md](AUDIT.md) finding 3).

## 3. Contention — no enrolment on record

`examples/client_mandate.py`, the weaker deployment. The mandate cannot tell owner from thief, so
it protects the incumbent and records the dispute instead of picking a winner.

```
A counter 0,1,2 : accepted
B counter 0     : REJECTED -- continuity contention, second instance claims this identity
A afterwards    : ACCEPTED -- still serving
```

## What this run does and does not show

It shows, on live silicon: relay resistance with a genuinely stolen key, first-message prevention
of re-hosting, survival of the victim under both modes, and a verifier that path-validates to the
AMD root rather than trusting the first key it is handed.

It does not show: any platform other than GCP SEV-SNP Milan; the masked-anchor case, which by
construction cannot be demonstrated as working because HATLS refuses to operate there; sealing;
or the physical-insider case.

---

# HATLS on real hardware: the full cycle, including re-hosting and revocation

Live run 21 September 2026, run id `20260921T135827Z`. Two genuine AMD SEV-SNP guests on Google
Cloud, deleted immediately after. Evidence: `evidence/20260921T135827Z/` (guestA.json, guestB.json,
verdict.json) — real 1184-byte VCEK-signed reports, verified against AMD KDS.

## Setup

| guest | role | zone | chip (CHIP_ID, first 8) | TIK |
|---|---|---|---|---|
| hatls-a | victim | europe-west4-b | `761022d0abefa2af` | shared prime256v1 key |
| hatls-b | re-host attacker | europe-west4-a | `15f90cb088627a60` | **same key** |

Both guests ran the HATLS probe: a real TLS 1.3 server that, per session, derives the RFC 9266
exporter and walks a continuity chain, requesting a real SEV-SNP report for each link with
`REPORT_DATA = SHA-512("HATLS-continuity-v0" || post_link)`. The operator ran the client + shared
Mandate, verifying every report's ECDSA-P384 signature against the VCEK AMD KDS issues for that chip.

## Result — the full cycle, measured

    VICTIM  guest A (chip 761022d0), continuity chain:
       counter 0: accepted   (real report, signature valid to AMD, link chains)
       counter 1: accepted
       counter 2: accepted
    RE-HOSTING  guest B (chip 15f90cb0), SAME TIK:
       counter 0: REVOKED  -- "same identity on a different chip (re-hosting)"
    VICTIM A tries to continue:
       counter 0: DECLINED -- identity already revoked

Mandate audit log:
    accept              TIK 3059..  counter 0  chip 761022d0  new
    accept              TIK 3059..  counter 1  chip 761022d0  cont
    accept              TIK 3059..  counter 2  chip 761022d0  cont
    revoke-fork-chip    TIK 3059..  761022d0 -> 15f90cb0  counter 0
    declined-revoked    TIK 3059..

## What this demonstrates, on hardware

1. The two SEAT camps are unified in one running protocol: the intra transcript link and the post
   exporter link chain together, each bound to real silicon by a real SEV-SNP report.
2. The mandate that the WG use-cases (3.8.1) asks for — "continuity with a particular platform
   instance ... a means to reject compromised authentication credentials" — works: a stolen key
   presented on genuine-but-different silicon is detected and revoked. §4.8 says the state of the
   art does not achieve continuity; this does, and it did it on two live chips.
3. The non-copyable anchor holds: guest B held the same TIK and produced perfectly valid SEV-SNP
   Evidence; it was rejected solely because the CHIP_ID differed. The attacker can steal the key;
   it cannot steal the chip.

## Honest scope of this run

- This proves detection-and-revocation of re-hosting, which is the 3.8.1 mitigation, not prevention
  of the first message under a stolen key (that remains the stated ceiling).
- Two zones, one cloud, one silicon vendor. Cross-cloud (AWS, Azure) and cross-vendor (TDX) and real
  Internet-latency scale are the next runs; the mandate logic is TEE-agnostic and unchanged.
- The relay and legitimate-reconnect cases are proven locally (run_local.py); folding them into a
  single hardware transcript is a next step. The re-hosting + revocation core — the part nobody has
  built — is done on live hardware here.
- Cost: two n2d-standard-2 SEV-SNP guests for ~15 minutes. Cents.

Serhii Nikolaichuk / The Capital Index, Austin, Texas


---

# Update: enrolment PREVENTION on live hardware, run `enroll-20260921T141024Z`

The v0 ceiling ("first message under a stolen key passes") is now removed for the key-theft case.
Two fresh SEV-SNP guests, same TIK, deleted after.

    ENROLMENT  guest A (chip 761022d0), TACRA-style: REPORT_DATA = SHA-512(nonce || CSR)
               -> chip signs that this key was created on it; mandate records TIK -> chip A.
    ATTACK     guest B (chip 15f90cb0), same TIK, presents a continuity chain:
               -> BLOCKED ON THE FIRST MESSAGE, no victim active
                  "key presented on a chip it was not enrolled on"
    CONTROL    guest A on its enrolled chip: accepted.

Mandate log:
    enrolled            TIK 3059..  chip 761022d0
    blocked-enrollment  TIK 3059..  enrolled 761022d0  presented 15f90cb0  counter 0
    accept              TIK 3059..  counter 0  chip 761022d0  new

This is prevention, not detection: the stolen key is inert on any chip but the one it was enrolled
on, caught on the message that carries it, with no second observation needed. The attacker cannot
forge CHIP_ID (chip-signed) and cannot make Evidence for chip A (does not hold it). The residual
floor is an insider physically on chip A itself — see THREAT-LAYERS.md.
Evidence: evidence/enroll-20260921T141024Z/ (real reports, verified to AMD KDS).
