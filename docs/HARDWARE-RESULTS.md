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
