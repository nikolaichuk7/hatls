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
pip install -r requirements.txt
PYTHONPATH=. python3 examples/run_local.py     # nine scenarios end to end on a mock chip
PYTHONPATH=. python3 examples/attack.py        # try to break it: 8 attacks, see the verdicts
PYTHONPATH=. python3 examples/relay_demo.py    # a real TLS relay, with the real stolen key
PYTHONPATH=. python3 bench/benchmark.py        # reproduce every number in the table below
```

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
[docs/HARDWARE-RESULTS.md](docs/HARDWARE-RESULTS.md).

## Repository layout

```
hatls/         the protocol + TEE backends (mock for local, SEV-SNP for hardware)
tools/         probes that run INSIDE a confidential guest
examples/      operator-side: the demo, the attack playground, the hardware runner
scripts/       launch a real SEV-SNP guest
docs/          design, threat model, gap analysis, hardware results
evidence/      real attestation verdicts from the hardware runs
```

## Performance and correctness (measured)

Numbers reproduce from `examples/` on a mock chip; the beacon cost is from `tools/liveness_probe.py`
on a real AMD SEV-SNP chip.

| Question a deployer asks | Measured answer |
|---|---|
| Does it slow the connection? | one attestation report at setup (~8 ms, once); after that the per-step link is **2.5 microseconds** (~400k/sec) |
| How fast can the mandate verify? | **~1 ms per check incl. ECDSA verify, ~920 checks/sec per core**, scales with cores |
| Liveness beacon cost on real silicon | **7.96 ms median**, up to ~125/sec; you emit one per policy interval (e.g. once a second), not per packet |
| Will it reject legitimate users? | legitimate reconnects from the enrolled instance: **0 false rejects / 500** |
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
- **The anchor answers "same silicon", not "same instance".** Two guests on one socket share a
  `CHIP_ID`, so re-hosting between VMs on one physical machine is invisible; a guest migrated to
  another socket reads as a fork. That is the ceiling of the claim we chose, not a bug we can
  patch — see the open question below.
- **The mandate's ledger is durable only if you give it a store.** The default `MemoryStore` keeps
  enrolment, revocation and contention in memory, so a restart loses them — and a lost ledger is
  indistinguishable from an identity that was never enrolled, which would quietly downgrade the
  guarantee. Two independent fixes exist and both are one argument: `store=FileStore(path)` makes
  the ledger survive the process, and `require_enrolment=True` makes an unknown identity a refusal
  instead of a downgrade, so a wiped ledger fails closed. `examples/attack.py restart` shows the
  default and both fixes side by side. Session chains are deliberately **not** stored: a connection
  dies with the process and the next one starts its own chain.
- **The mandate is still a single trusted component.** It is not replicated, it issues no receipts,
  and nothing lets a third party audit its answers after the fact — so it is not the transparency
  service the vocabulary of SCITT would imply. It is also absent from the threat model: what a
  relying party may still decide when the mandate is unavailable, or lying, is unspecified.
- **Contention is recorded but never resolved.** Refusing to revoke on an unauthenticated claim
  removed an availability attack; it did not say who adjudicates a dispute, on what evidence, or
  within what bound. That is the next piece of work, and it is operational semantics rather than
  channel cryptography.
- **No instance anchor on some platforms.** Re-host detection rests on the SEV-SNP `CHIP_ID`. Under
  a shared-tenancy VLEK that field is **all zeros**: in our own archive, six distinct AWS instances
  report the same 64 zero bytes, and the firmware does *not* set `MASK_CHIP_KEY` to say so. On such
  a platform HATLS **fails closed** rather than pretending, and `require_anchor=False` lets a
  deployer accept the downgrade knowingly: ordering and relay defence still hold, re-host detection
  does not. Which claim *should* carry instance identity across SNP, TDX and Nitro is an open
  question we would like the working groups to settle.
- Measured on one cloud and one silicon vendor so far. AWS, Azure, and Intel TDX are next.
- The physical-insider case is narrowed, not eliminated — it cannot be, by the nature of any
  signing key. The beacon interval bounds detection resolution, not the attacker's window.
- Sealing the identity key to its chip is part of the design but is **not implemented here**; the
  launcher deliberately ships one key to two guests, which is the stolen-key model this repository
  demonstrates against.
- No formal model yet. The guarantees here are measured and tested, not machine-proved; a
  ProVerif/Tamarin treatment of the binder and the mandate is the obvious next step.
- The early binder runs over a session context both endpoints derive independently, not over the
  true TLS handshake transcript, which needs a hook into the TLS stack.

## Relationship to IETF

HATLS is a contribution toward the SEAT working group's problem, building on
`draft-ietf-seat-use-cases`, `draft-fossati-seat-early-attestation` (intra),
`draft-fossati-seat-expat` (post), and `draft-novak-rats-tacra` (enrolment). It composes them
rather than competing with any one.

## License

Apache-2.0. © 2026 Serhii Nikolaichuk, The Capital Index, Austin, Texas.
