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
| 7 | Re-hosts on a platform whose **silicon claim is masked** (AWS shared-tenancy VLEK) | **the instance anchor, `REPORT_ID`** — this is no longer a gap | prevent, first message | yes — live AWS run, two regions: `CHIP_ID` zeroed with `MASK_CHIP_KEY` clear and one VLEK key for the region, impostor still refused by the anchor |
| 8 | Re-hosts on a platform with **no instance claim at all** | none — the question is undecidable there | **fails closed** | Intel TDX measured: two TDs from one image differ only in `MROWNER`, which the host supplies |

Layers 2-5 either prevent the attack outright or catch it on the message that carries it. Layer 1
is designed but not implemented here. Layer 6 — an adversary with physical control of the exact
enrolled chip while it runs — survives; it is no longer a key-theft attack but physical possession
of one specific machine. Layer 7 used to be a gap and is now covered, because identity moved off
the silicon claim and onto the instance claim. Layer 8 is not a defence at all: it is a platform
where the question cannot be asked, and the honest response is to refuse rather than to pretend.

Rejection targets the presenter. An impostor cannot revoke the identity it claims; revocation is an
explicit operator act ([AUDIT.md](AUDIT.md) finding 3).

## The mandate itself is not in this model, and that is now the largest gap

Every row above assumes the mandate is correct and available. It is neither modelled nor durable:
its nonces, enrolment records and ledger are in process memory, so a restart loses the enrolment
records and **silently downgrades an enrolled identity to the weaker no-enrolment mode**. Run
`PYTHONPATH=. python3 examples/attack.py restart` to watch an impostor, blocked a moment earlier,
be accepted. Two tests assert this weakness deliberately so that it cannot be forgotten.

Contention has the same shape: the mandate now refuses to destroy an identity on an unauthenticated
claim, which removed an availability attack, but nothing says who resolves the dispute, on what
evidence, or in what time. Durable replicated state, an audit trail, a resolution procedure, and
what a relying party may decide when the mandate is unavailable or lying, are the next body of
work — and they are operational semantics rather than channel cryptography.

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


## What a machine has checked, and what it has not

`formal/hatls.pv` states the binder and the mandate in the applied pi calculus and ProVerif 2.05
proves three things about them: that anything the mandate accepts was attested by that instance for
the exporter the mandate derived itself, that the accepting instance is the enrolled one, and that
a step accepted under one session context was produced under it. The attacker is Dolev-Yao, the
identity key is handed to it in the clear, and sessions are unbounded. A fourth query checks the
honest run is still reachable, because a protocol nobody can complete satisfies everything.

`formal/hatls-relay-defect.pv` is the same model with the v0.1 defect restored -- the mandate
taking the exporter off the wire -- and ProVerif finds the relay. Two of the three queries stay
true there, which is the shape of the real defect: a relay forwards genuine evidence from the
genuine enrolled chip, so only the binding to *this* session breaks.

Outside that model, and so not proved by it: TLS itself, the transfer grant, revocation, the ledger
and its receipts, and the hardware-witnessed head. Those rest on the arguments above and on tests.
