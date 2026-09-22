# HATLS — Hybrid Attested TLS with a Continuity Mandate

[![CI](https://github.com/nikolaichuk7/hatls/actions/workflows/ci.yml/badge.svg)](https://github.com/nikolaichuk7/hatls/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-research%20prototype-orange.svg)](docs/HARDWARE-RESULTS.md)
[![Hardware](https://img.shields.io/badge/measured%20on-AMD%20SEV--SNP-green.svg)](docs/HARDWARE-RESULTS.md)

**Know that the confidential machine answering you is the same enrolled machine it was at the first
message — and find out within one message when it stops being.**

HATLS is a **continuity layer** for attested TLS. A transport binder proves "this session reaches a
genuine TEE"; HATLS adds what the SEAT working group's own use-cases document asks for and leaves
unspecified: **continuity to a specific instance, and what happens when an identity forks.**

It is **post-handshake by nature**, and says so. Evidence binds the TLS exporter, which exists only
after the handshake completes, so every attestation HATLS delivers is a post-handshake one. The
early binder over the session context is an input to the first link, not a second delivery channel.
It sits above `draft-fossati-seat-early-attestation` and `draft-fossati-seat-expat` rather than
competing with either.

> Everything here is measured on real AMD SEV-SNP hardware, not simulated. Reproduce it yourself in
> two minutes locally, or against your own confidential VM. This is a research prototype, not a
> finished standard.

---

## Why this matters

When you run a workload in someone else's data centre — a model, patient records, signing keys — you
want proof that the machine holding your secret is a genuine confidential computer in a known-good
state. Today that proof is usually checked **once, at connection time**. A machine that is healthy at
the handshake and compromised a minute later looks identical to the relying party.

Worse: if an attacker **steals the server's identity key**, it can run that key on its own genuine
confidential machine and is cryptographically indistinguishable from the real server. The published
attacks against shipped products (CVE-2026-33697 and others) exploit exactly this class.

HATLS narrows the attacker, layer by measured layer:

| The attacker managed to… | HATLS response | Prevent / detect |
|---|---|---|
| Copy the key **file** | sealing the key to its chip (SEV-SNP derived key) — *designed, not implemented in this repository* | prevent |
| Extract the **live key**, run it on another chip | enrolment: wrong chip → blocked on the **first message** | prevent |
| Open an independent session to another party | shared mandate keyed by identity, not connection | prevent |
| Replay or reorder within a session | continuity chain + counter | detect, same message |
| Relay a genuine session | exporter binding | detect |
| Be a **physical insider on the exact chip** | liveness beacons: the chip can emit one every **7.96 ms**, so that is how finely an interruption can be seen | narrowed, not closed |

The only survivor is an insider physically at the enrolled chip. We do not claim to eliminate it,
and we are careful about what the 7.96 ms means: it is how fast the chip can produce a fresh
liveness beacon, which bounds the **resolution of detection**, not the attacker's window. While the
key is in cleartext in guest memory to sign at all, that window is the life of the process.

There is also a platform where the central guarantee does not hold at all, and it is named up
front: see *no instance anchor* under [Honest limits](#honest-limits).

---

## Quickstart — no cloud, no hardware (2 minutes)

```bash
git clone https://github.com/nikolaichuk7/hatls && cd hatls
pip install -r requirements.txt -r requirements-dev.txt
PYTHONPATH=. python3 -m pytest tests/ -q       # the whole suite, no cloud and no hardware
PYTHONPATH=. python3 examples/run_local.py     # eleven scenarios end to end on a mock chip
PYTHONPATH=. python3 examples/attack.py        # try to break it: 13 attacks, see the verdicts
PYTHONPATH=. python3 examples/relay_demo.py    # a real TLS relay, with the real stolen key
PYTHONPATH=. python3 bench/benchmark.py        # reproduce every number in the table below
```

Nothing above touches a network or a cloud account. `requirements.txt` is what the protocol needs;
`requirements-dev.txt` adds pytest, and is separate so that using the library does not drag a test
runner in with it.

`attack.py` prints `STOPPED` for every attack the mandate catches and is honest about the weaker
no-enrolment mode. Add your own attack to `examples/attack.py` and see if it gets through.

## Run it against a real confidential VM

Requires a Google Cloud project with SEV-SNP capacity:

```bash
scripts/launch.sh guest-a europe-west4-b        # a real SEV-SNP guest runs the HATLS server
scripts/launch.sh guest-b europe-west4-a        # SAME identity key => a re-hosting attacker
PYTHONPATH=. python3 examples/client_mandate.py <ip-a> <ip-b>   # full cycle, verified to AMD KDS
PYTHONPATH=. python3 examples/enroll_run.py     <ip-a> <ip-b>   # attacker blocked on first message
```

The guests produce genuine 1184-byte SEV-SNP reports; signatures are checked against AMD's key
distribution service. Delete the VMs when done (the scripts remind you).

---

## How it works

```
  after the handshake completes                        continuously
  ─────────────────────────────                        ────────────
  intra_link       ─►   post_link_0          ─►        post_link_1  ─►  ...
  = f(session ctx,      = f(exporter,                  = f(exporter,
      identity key)         prev, counter=0)               prev, counter=1)
      │                      │                             │
      │ a binder both ends   │ shared secret, ordered      │ each link is carried in a
      │ derive independently │                             │ real hardware attestation report
      └──────────────────────┴─────────────────────────────┘

  This is NOT early attestation. Every value above lives after the handshake: the session
  context and the exporter both come out of the completed TLS 1.3 key schedule.
  draft-fossati-seat-early-attestation delivers Evidence *inside* the handshake. HATLS does
  not, and does not claim to. `intra_link` is the first link of the chain, nothing more.

  Mandate (a shared authority over an identity -- in this prototype an in-process store,
  NOT an append-only log: no receipts, no Merkle tree, no independent auditor):
    • enrolment  : the chip signs "this key was born on me"  → wrong chip blocked on first message
    • continuity : each link must chain from the last         → replay / relay / splice caught
    • instance anchor: the identity must stay on its instance  → re-hosting caught, impostor refused
```

A rejected presenter never revokes the identity it claims. With enrolment on record the mandate
knows which instance is legitimate and simply refuses the other one; without it, a second instance
is recorded as *contention* and the incumbent keeps serving. Revocation is an explicit operator
act, so a stolen key cannot be turned into a weapon against its owner.

**Every defect found in v0.1, how it was found and what changed:** [docs/AUDIT.md](docs/AUDIT.md).

Full design in [docs/DESIGN.md](docs/DESIGN.md); the layered threat model in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md); why the working group needs this in
[docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md); the hardware runs in
[docs/HARDWARE-RESULTS.md](docs/HARDWARE-RESULTS.md); and, goal by goal against the working
group's own list in draft-ietf-seat-use-cases-01 Section 4 — including the three goals this does
not address — [docs/SEAT-GOALS.md](docs/SEAT-GOALS.md).

## Repository layout

```
hatls/         the protocol + TEE backends (mock for local, SEV-SNP for hardware)
tools/         probes that run INSIDE a confidential guest
examples/      operator-side: the demo, the attack playground, the hardware runner
scripts/       launch a real SEV-SNP guest
docs/          design, threat model, gap analysis, hardware results, the SEAT goals statement
evidence/      real attestation verdicts from the hardware runs
```

## Performance and correctness (measured)

Numbers reproduce from `examples/` on a mock chip; the beacon cost is from `tools/liveness_probe.py`
on a real AMD SEV-SNP chip.

All of it runs from a clean checkout with no cloud account: **150 tests**, **13 of 13 attacks
stopped**, a real TLS relay on localhost, and a benchmark that reproduces every number below.

| Question a deployer asks | Measured answer |
|---|---|
| Does it slow the connection? | one attestation report at setup (~8 ms, once); after that the per-step link is **2.5 microseconds** (~400k/sec) |
| How fast can the mandate verify? | **~1 ms per check incl. ECDSA verify, ~920 checks/sec per core**, scales with cores |
| Liveness beacon cost on real silicon | **7.96 ms median**, up to ~125/sec; you emit one per policy interval (e.g. once a second), not per packet |
| Will it reject legitimate users? | legitimate reconnects from the enrolled instance: **0 false rejects / 500** (no migration in those 500; a migration to other silicon is the separate false-positive risk below) |
| Will an impersonation slip through? | stolen key on a different instance: **0 missed / 500** |
| Does normal in-session traffic break the chain? | **0 false breaks / 500** |
| Can one identity hold several connections at once? | 16 parallel connections: **0 false breaks / 496** |
| Is a relayed exporter ever accepted? | **0 accepted / 500** |

Reproduce all of it with `PYTHONPATH=. python3 bench/benchmark.py` (set `HATLS_BENCH_N` to change
the trial count). The measured mandate check is **0.78 ms including the ECDSA verify**.

The expensive part of any attested-TLS design is appraising the Evidence itself (seconds); HATLS adds
nothing to that hot path — the continuity layer is microsecond arithmetic in the background. A user
does not perceive a speed difference.

**One honest false-positive risk:** if the cloud *live-migrates* a workload to a different physical
chip, the chip identifier changes and the mandate reads it as a fork. In practice SEV-SNP confidential
VMs are not live-migrated (the maintenance policy terminates them), so this does not arise there;
where migration is possible, it is closed by the platform signing a migration statement that the
mandate accepts. This is an open item, stated rather than hidden.

## Honest limits

- A research prototype, not an IETF standard. Standardisation is a multi-year process.
- **The identity is proved by possession, not by a CA.** With no `ca_file` the client runs
  `VERIFY_NONE`, and that is deliberate: TLS 1.3 CertificateVerify already proves the peer holds
  the private half of the certificate it presented, and whether *that* key is legitimate is the
  mandate's answer, not a CA's. So HATLS **does not validate a certificate chain** unless you pass
  `ca_file`, and nothing here should be read as "we check the certificate" in the PKI sense.
- **The mandate's ledger is durable only if you give it a store.** The default `MemoryStore` keeps
  enrolment, revocation and contention in memory, so a restart loses them — and a lost ledger is
  indistinguishable from an identity that was never enrolled, which would quietly downgrade the
  guarantee. Two independent fixes exist and both are one argument: `store=FileStore(path)` makes
  the ledger survive the process, and `require_enrolment=True` makes an unknown identity a refusal
  instead of a downgrade, so a wiped ledger fails closed. `examples/attack.py restart` shows the
  default and both fixes side by side. Session chains are deliberately **not** stored: a connection
  dies with the process and the next one starts its own chain.
- **The mandate is trusted, and now at least accountable.** Every decision is a leaf in an
  append-only Merkle log and comes back as a receipt — entry, inclusion proof and signed tree head
  — so it can no longer deny what it said or claim what it did not. A consistency proof between two
  heads stops it rewriting its past. Equivocation it cannot be *prevented* from committing, only
  proved: two heads it signed where neither extends the other are the evidence.
  The head of that log was still the mandate's own word, so the head now goes into the hardware:
  the verifier hands its current head to the attester, the chip binds it into `REPORT_DATA`, and
  the mandate cannot mint a report claiming a different ledger state because the signing key is the
  chip's. Verified on live SEV-SNP. The limit of that: it stops a mandate **lying later**, not a
  mandate and a guest **colluding at the time** — between them they choose the head, and the chip
  signs what it is given. The property bites once the report has left their joint control.
- **Two mandates over one identity: divergence is detected, not prevented — this is not a
  federation.** There is no shared state and nothing coordinates the two. Preventing it needs
  consensus, with the availability price that implies. Detecting it needs only that the two claims
  meet somewhere — and there is a channel here that Certificate Transparency does not have, where
  gossip between clients is the unsolved part. **The attester is the gossip.** Both mandates
  already trust the same TEE, so one hardware report carries *both* their claimed heads at one
  moment, under a key belonging to neither. A mandate that later produces a history its witnessed
  head does not extend is caught with that one report, and it never had to be online for, or
  trusted by, the other. What remains unspecified is what a relying party may decide while a
  mandate is unavailable, and there is still no replication.
- **A disputed identity is resolved by its owner, not by the mandate — and that is a new key to
  protect.** Two instances presenting genuine evidence for one identity cannot be told apart by
  looking harder: a thief and an operator recovering a dead machine produce identical reports. So
  an identity may name a **transfer authority** at enrolment, and only a grant signed by that key —
  single-use, time-bounded, optionally pinned to the instance being left — moves it. The mandate
  enforces; it does not adjudicate. An identity that names no authority cannot be moved at all,
  which is the safe default and also means a dead machine ends it. The honest cost: that authority
  key now protects the identity, so losing it strands the workload and stealing it moves the
  workload — so **it must not live inside the attested VM**, or the "owner" is the same process an
  attacker has already taken. There is no k-of-n and no recovery path for a lost authority.
  Three more limits of the grant, stated rather than discovered: it names **instances**, so it can
  only move what the mandate can identify; it carries **no mandate identifier at all**, so a second,
  independent mandate holding the same enrolment would accept the very same grant — spent nonces
  live in one process and nothing binds a grant to the mandate that issued the challenge; and `nbf`/`exp` are the issuer's clock, which makes the window an
  operational bound and not a cryptographic one. The signed bytes are canonical JSON, which is
  adequate here and is **not** an interoperable encoding — a specification would use COSE.
- **Identity is the instance claim, not the silicon.** HATLS anchors on SEV-SNP `REPORT_ID`, which
  the AMD-SP generates per guest and which persists for that guest's lifetime; it is not an input
  to `SNP_LAUNCH_START`, so the hypervisor cannot choose it. `CHIP_ID` is carried separately as a
  *place* claim and is not identity: two guests on one socket share it, and a shared-tenancy VLEK
  report zeroes it — in our archive six distinct AWS instances report 64 zero bytes while their
  `REPORT_ID`s are all distinct, and on that platform the VLEK **signing key is shared region-wide
  too**, so neither the chip nor the signature separates two machines. A deployment that wants
  silicon pinning asks for it with `require_place=True`.
  The consequence to understand: `REPORT_ID` travels with a guest across migration (the firmware
  marks it `Migrated? = Yes`), so **where migration is enabled the migration agent is inside the
  trust boundary of this identity**. In our corpus `REPORT_ID_MA` is all-ones on all 73 GCP
  reports, i.e. no migration agent — a measured fact about those deployments, not a guarantee.
  What the equivalent claim is on TDX and Nitro is still open.
- **Measured on GCP and AWS, both AMD SEV-SNP; TDX measured and found wanting; Azure blocked.**
  GCP carries the full cycle including the TLS binding. AWS proves the instance anchor on shared
  tenancy, where `CHIP_ID` is zeroed and the VLEK signing key is shared region-wide — but not the
  TLS binding, because those guests have no inbound network and report through the serial console,
  so their exporter is supplied rather than derived from a live handshake.
  On **Intel TDX** the anchor does not exist: two TDs from one image differ in exactly one
  `TDREPORT` field, `MROWNER`, and the host VMM supplies that one. A design that anchors on
  SEV-SNP does not port to TDX by renaming a field — see
  [ietf/research](https://github.com/nikolaichuk7/hatls) notes and `evidence/tdx-claims-*`.
  **Azure is untested**: confidential-VM quota is 0 in all nine regions checked, for both the
  `DCADSv5` and `ECADSv5` families, so the VMs cannot be created without a quota grant.
- The physical-insider case is narrowed, not eliminated — it cannot be, by the nature of any
  signing key. The beacon interval bounds detection resolution, not the attacker's window.
- Sealing the identity key to its chip is part of the design but is **not implemented here**; the
  launcher deliberately ships one key to two guests, which is the stolen-key model this repository
  demonstrates against.
- **The binder, the mandate's appraisal of one step, and the ORDER of a three-link chain are
  machine-proved. The rest is not.** Out of the model: the transfer grant, revocation, the ledger,
  receipts, the hardware-witnessed head, cross-mandate detection, and TLS. ProVerif 2.05 proves,
  against a Dolev-Yao attacker with the identity key handed to it in the clear, a thief's TEE that
  signs anything, the thief as TLS peer of sessions with both ends, and unboundedly many parallel
  sessions, that anything the mandate accepts at position *n* was attested by the enrolled
  instance, for the exporter the mandate derived itself, under the session it was produced for,
  **at position *n* and before acceptance** — non-injectively and injectively — and that the
  honest run is still reachable, so none of it holds vacuously. Two broken models are included as
  checks that the prover is sensitive rather than agreeable: with the v0.1 defect put back it finds
  the relay; with the binder held constant for the connection it finds the resend of position 0's
  Evidence at position 1, which is draft-fossati-seat-early-attestation-07 Section 8.4 stated in
  prose. See [formal/](formal/).
- HATLS's own first link runs over a session context both endpoints derive independently, not over
  the true TLS handshake transcript. The hook that would allow the transcript now exists —
  `hatls/transcript.py` records ClientHello and ServerHello over memory BIOs and computes
  draft-fossati-seat-early-attestation's Section 5.1.1 binder from them, byte-checked against RFC
  8448, and the reattestation experiment runs on it — but moving HATLS's first link onto it is a
  protocol change not yet made.

## Relationship to IETF

HATLS is a contribution toward the SEAT working group's problem, building on
`draft-ietf-seat-use-cases`, `draft-fossati-seat-early-attestation` (intra),
`draft-fossati-seat-expat` (post), and `draft-novak-rats-tacra` (enrolment). It composes them
rather than competing with any one.

## License

Apache-2.0. © 2026 Serhii Nikolaichuk, The Capital Index, Austin, Texas.
