# Closing the ceiling: layered defence against a stolen identity key, each layer measured

The honest limit of HATLS v0 was: re-hosting is detected and revoked, but the FIRST message under a
stolen key passes, because the mandate needs to see a fork. This note removes that limit for every
case except one, names the one, and shows each layer is something we have measured — not argued.

The key insight: turn the mandate from a fork-detector (needs two chains) into an enrolment-checker
(needs a baseline). The chip signs, once, that a key was born on it. After that, the same key on any
other chip is rejected on the first message, with no victim present.

## The attacker, narrowed layer by layer

| # | What the attacker achieved | Layer that stops it | Prevent or detect | Measured |
|---|---|---|---|---|
| 1 | Copied the TIK **key file** | **Sealed TIK**: file unseals only on its own chip | prevent | **designed, NOT implemented in this repository** — `scripts/launch.sh` deliberately ships one key to two guests, which is the stolen-key model demonstrated here |
| 2 | **Extracted the live key**, runs it in its **own** TEE | **Enrolment gate**: anchor in Evidence != the instance the key was enrolled on | prevent, first message | yes — hardware run 21 Sep; enrolment now binds a real CSR with proof of possession (see [AUDIT.md](AUDIT.md) finding 2) |
| 3 | Same, opens an **independent** session to a different Relying Party | **Shared ledger + enrolment**: the anchor baseline is per-identity even though the chain is per-connection | prevent, first message | yes — local, no victim needed |
| 4 | Replays / reorders links **within** a legitimate session | **Continuity chain + counter** | detect, same message | yes — HATLS hw run, 21 Sep |
| 5 | Relays a genuine session (holds the key) | **Exporter link** (post binder), derived by the verifier from its OWN session | detect, first post link | yes — `examples/relay_demo.py`, real TLS + real relay, in CI. v0.1's client read the exporter off the wire and accepted relays ([AUDIT.md](AUDIT.md) finding 1) |
| 6 | **Physically on the enrolled chip** (insider / stolen live machine) | **Continuity liveness + place** | detect (interruption / location) | partially — beacon cadence measured at 7.96 ms, which bounds detection *resolution*, not the attacker's window |
| 7 | Re-hosts on a platform that **exposes no instance anchor** (AWS shared-tenancy VLEK) | none — the guarantee does not exist there | **fails closed** | yes — 15 archived VLEK reports carry an all-zero `CHIP_ID` with `MASK_CHIP_KEY` clear ([AUDIT.md](AUDIT.md) finding 4) |

Layers 2-5 either prevent the attack outright or catch it on the message that carries it. Layer 1
is designed but not implemented here. Layer 6 — an adversary with physical control of the exact
enrolled chip while it runs — survives; it is no longer a key-theft attack but physical possession
of one specific machine. Layer 7 is not a defence at all: it is a platform where the central claim
cannot be made, and the honest response is to refuse rather than to pretend.

Rejection targets the presenter. An impostor cannot revoke the identity it claims; revocation is an
explicit operator act ([AUDIT.md](AUDIT.md) finding 3).

## Why enrolment breaks the ceiling (the new part)

use-cases 3.8.1 says the attack works when "the appraisal policy does not expect the key to have been
created in the Target Environment." Enrolment is exactly that expectation, made concrete and signed
by hardware:

    enrolment (once):  REPORT_DATA = SHA-512(nonce || CSR)  -> VCEK-signed report binds the key's
                       public part to CHIP_ID (this is TACRA, which we already built and measured).
    every session:     the mandate checks the Evidence chip against the enrolled chip. Different
                       chip -> blocked on the first message, no fork, no victim.

The attacker cannot forge CHIP_ID (it is inside the chip-signed report). The attacker cannot make
Evidence for the enrolled chip (it does not have that chip). So the stolen key is inert anywhere but
its birth chip. This is prevention, and it needs no second observation.

## The one residual case, stated honestly

Layer 6 is the true floor: an insider physically holding the enrolled chip while it is live, with the
key extracted in-memory during use. No key management reaches it, because the key must be in
cleartext on that chip to sign. But note what enrolment has done to the attacker's job: from "steal a
key, use it anywhere" down to "be physically present at one specific chip in one specific data centre
and extract its key in use without interrupting it." Against even that:

- **Liveness**: two live streams under one enrolled identity are a conflict the mandate sees (same
  chip cannot serve two ordered chains without a counter collision). Interrupting the chip to seize
  it breaks the chain — the mandate sees the gap (our failover drills measure this as RTO).
- **Place**: the enrolled chip is in one location. A geographic Attestation Result (our geoar work)
  lets a policy require that location, so a key used from elsewhere is rejected even on the right
  chip class.
- **Never-extractable key**: if the TIK is a vTPM non-extractable key (we bound vTPM to SEV-SNP on
  Azure), the insider cannot extract it at all and must use the chip in situ, which liveness+place
  then constrain.

## What is new here, honestly

Enrolment (TACRA), continuity, mandate, place, sealing, vTPM binding — each exists. What no one has
done is compose them into one measured protocol where the attacker is narrowed, layer by layer, from
"anyone with the key" to "an insider physically holding one running chip", with every layer backed by
a hardware measurement, and the two SEAT camps (intra transcript + post exporter) carried underneath.
That composition, and the honest floor it reaches, is the contribution.

Next hardware run: enrolment prevention on live chips (guest A enrols; guest B, same key, blocked on
first message), then the full six-layer transcript across clouds.

Serhii Nikolaichuk / The Capital Index, Austin, Texas
