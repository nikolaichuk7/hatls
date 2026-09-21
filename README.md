# HATLS — Hybrid Attested TLS with a Continuity Mandate

[![CI](https://github.com/nikolaichuk7/hatls/actions/workflows/ci.yml/badge.svg)](https://github.com/nikolaichuk7/hatls/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-research%20prototype-orange.svg)](docs/HARDWARE-RESULTS.md)
[![Hardware](https://img.shields.io/badge/measured%20on-AMD%20SEV--SNP-green.svg)](docs/HARDWARE-RESULTS.md)

**Prove that the confidential machine on the other end of a TLS connection is genuine — and stays
genuine — for the whole conversation, not just at the start.**

HATLS unifies the two approaches the IETF SEAT working group is choosing between (attestation
*inside* the TLS handshake and attestation *after* it) and adds the piece the working group's own
use-cases document says is needed but leaves unspecified: **continuity to a specific hardware
instance, with revocation the moment an identity forks.**

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
| Copy the key **file** | sealed key opens only on its own chip | prevent |
| Extract the **live key**, run it on another chip | enrolment: wrong chip → blocked on the **first message** | prevent |
| Open an independent session to another party | shared mandate keyed by identity, not connection | prevent |
| Replay or reorder within a session | continuity chain + counter | detect, same message |
| Relay a genuine session | exporter binding | detect |
| Be a **physical insider on the exact chip** | liveness + place; window **measured (~8 ms)**, not assumed | narrowed, quantified |

The only survivor is an insider physically at the enrolled chip — and even then its attack window is
a measured number, because the key must be in cleartext on the chip to sign. We do not claim to
eliminate it; we quantify it.

---

## Quickstart — no cloud, no hardware (2 minutes)

```bash
git clone https://github.com/nikolaichuk7/hatls && cd hatls
pip install -r requirements.txt
PYTHONPATH=. python3 examples/run_local.py     # the full cycle on a mock chip
PYTHONPATH=. python3 examples/attack.py        # try to break it: 8 attacks, see the verdicts
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
  handshake            after handshake              continuously
  ─────────            ───────────────              ────────────
  intra_link     ─►    post_link_0        ─►        post_link_1  ─►  ...
  = f(transcript,      = f(exporter,                = f(exporter,
      identity key)        prev, counter=0)             prev, counter=1)
      │                     │                            │
      │  public, early      │  shared secret, ordered    │  each bound to the chip by a
      └─── Camp 1 ──────────┴─── Camp 2 ─────────────────┘   real hardware attestation report

  Mandate (a shared, append-only authority over an identity, like a transparency log):
    • enrolment  : the chip signs "this key was born on me"  → wrong chip blocked on first message
    • continuity : each link must chain from the last         → replay / relay / splice caught
    • chip anchor: same identity must stay on the same chip   → re-hosting caught, key revoked
```

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
| Will it reject legitimate users? | legitimate reconnects from the same chip: **0 false rejects / 500** |
| Will an impersonation slip through? | stolen key on a different chip: **0 missed / 500** |
| Does normal in-session traffic break the chain? | **0 false breaks / 500** |

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
- Measured on one cloud and one silicon vendor so far. AWS, Azure, and Intel TDX are next.
- The physical-insider case is narrowed and its window measured, not eliminated — it cannot be,
  by the nature of any signing key.

## Relationship to IETF

HATLS is a contribution toward the SEAT working group's problem, building on
`draft-ietf-seat-use-cases`, `draft-fossati-seat-early-attestation` (intra),
`draft-fossati-seat-expat` (post), and `draft-novak-rats-tacra` (enrolment). It composes them
rather than competing with any one.

## License

Apache-2.0. © 2026 Serhii Nikolaichuk, The Capital Index, Austin, Texas.
