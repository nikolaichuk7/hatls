> **Read [AUDIT.md](AUDIT.md) first.** The run immediately below is the current one, made on
> 21 Sep 2026 with identity anchored on the instance claim. **Everything after it is a historical record of earlier runs,**
> kept unedited because evidence should not be rewritten after the fact.
>
> Those earlier runs were produced by v0.1, whose client read the TLS exporter and the identity key
> out of the peer's own message and whose enrolment never bound the key to the chip. What still
> stands in them: the reports are genuine, the chips and signatures are real, and re-hosting across
> two distinct chips was genuinely detected. What does not: any relay resistance they seem to
> imply, because the client of the day could not have detected a relay; and the revocation of guest
> A once guest B appeared, which is now understood as an attack on the victim, not a success.

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
