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

    enrolment (once):  REPORT_DATA = SHA-512(nonce || CSR)  -> a signed report binds the key's
                       public part to the INSTANCE it was born on (REPORT_ID). The CSR carries that
                       key and is self-signed by it, so the report is about this key and no other.
    every session:     the mandate compares the instance in the Evidence against the enrolled one.
                       Different instance -> blocked on the first message, no fork, no victim.

The claim is the instance, not the silicon. CHIP_ID is carried alongside as *place* and is a weaker,
different statement: two guests on one socket share it, and a shared-tenancy platform zeroes it
entirely -- on AWS, six machines in our archive and two in the live run report 64 zero bytes while
their REPORT_IDs are all distinct. A design anchored on the chip is blind exactly there, which is
why this one is not. `Mandate(require_place=True)` pins the silicon as well, for a deployment that
wants it.

The attacker cannot forge the instance claim (it is inside the chip-signed report, and the AMD-SP
generates it -- it is not among the SNP_LAUNCH_START inputs, so the hypervisor cannot choose it).
The attacker cannot produce Evidence for the enrolled instance, because it is not that instance. So
the stolen key is inert anywhere but where it was enrolled. This is prevention, and it needs no
second observation.

What it does NOT cover: REPORT_ID travels with a guest across a migration, so wherever migration is
enabled the migration agent sits inside the trust boundary of this identity. In our corpus
REPORT_ID_MA is all-ones on all 73 GCP reports, meaning no migration agent -- a measured fact about
those deployments, not a guarantee. And on Intel TDX no such claim exists at all: two TDs from one
image differ only in MROWNER, which the host supplies.

## Who may move an identity, and the key that decides it

Two instances presenting genuine evidence for one identity cannot be told apart by looking harder:
a thief and an operator recovering a dead machine produce the same reports, because in the evidence
they *are* the same. So the mandate does not adjudicate. An identity may name a **transfer
authority** at enrolment -- a key held by whoever owns the workload, not by the platform and not by
the mandate -- and only a grant signed by that key moves it. Grants are single-use, time-bounded,
and must name the instance being left; a grant that names none is a grant to abduct, and the
`any_origin` form that drops that requirement is a separate, logged, deliberate act. A destination
must be an instance the mandate has itself seen produce valid evidence, so nothing is written into
the ledger about a machine nobody has proved exists.

This adds a key to the threat model, and it is **stronger than the identity key it governs**: a
stolen TIK cannot move without a grant, while a stolen authority moves the TIK. It therefore must
not be held inside the attested VM -- if it is, the "owner" is the same process an attacker has
already taken, and the mechanism collapses into a second copy of the first problem. There is no
k-of-n and no recovery for a lost authority: losing it strands the identity.

A grant carries **no mandate identifier**. Spent nonces live in one process, so a second,
independent mandate holding the same enrolment would accept the same grant. That is the federation
problem, and it is not solved here.

## What the hardware witness protects against, and what it does not

Each decision is a leaf in an append-only log, and a receipt carries an inclusion proof and a
signed tree head, so the mandate cannot deny what it said or rewrite its past. The head of that log
was still its own word, so the head goes into the attestation: the verifier hands it over, the
guest binds it into REPORT_DATA, and the chip signs across it.

That protects against a mandate **lying later**. It does not protect against a mandate and a guest
**colluding at the time**: between them they choose which head goes in, and the chip signs whatever
it is given. The property becomes useful only once the report has left their joint control --
published to a third party, an auditor, or the workload owner. Until then it is their word,
jointly signed.

The same applies to two mandates over one identity. One report can carry both their heads, so a
mandate whose later history does not extend the head the chip saw is caught by that one report.
That is **detection after the fact, never prevention**: two mandates can still admit different
instances, and nothing here coordinates them. It is not a federation.

## The one residual case, stated honestly

Layer 6 is the true floor: an insider physically holding the enrolled chip while it is live, with the
key extracted in-memory during use. No key management reaches it, because the key must be in
cleartext on that chip to sign. But note what enrolment has done to the attacker's job: from "steal a
key, use it anywhere" down to "be physically present at one specific chip in one specific data centre
and extract its key in use without interrupting it." Against even that:

- **Liveness**: two live streams under one enrolled identity are a conflict the mandate sees (same
  chip cannot serve two ordered chains without a counter collision). Interrupting the chip to seize
  it breaks the chain — the mandate sees the gap, at a resolution bounded by how fast the chip
  can emit a fresh beacon (7.96 ms, `tools/liveness_probe.py`).
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
