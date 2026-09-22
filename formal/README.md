# Formal model

> **IN THE MODEL: the continuity binder, the mandate's appraisal of one step (`hatls.pv`), and
> the ORDERED CHAIN of three steps with the mandate's per-session state (`hatls-chain.pv`).**
> **OUT OF THE MODEL: the transfer grant, revocation, the ledger, receipts, the hardware-witnessed
> head, cross-mandate detection, and TLS itself.**
>
> Quote this line wherever the proof is mentioned. "HATLS has a formal model" is true and, without
> it, misleading: what is proved is the binder, not the protocol.

The review said it plainly: the tests show that the attacks we thought of are stopped, and say
nothing about the ones we did not. This is the answer to that, and it is deliberately narrow.

## What is here

- `hatls.pv` — the continuity binder and the mandate in the applied pi calculus, for ProVerif.
- `hatls-relay-defect.pv` — the same model with the v0.1 defect put back, as a check on the model.
- `hatls-chain.pv` — the chain: three links per session and a mandate that keeps state, against a
  stronger attacker than `hatls.pv` (see below). This is where **order** is proved.
- `hatls-constant-binder.pv` — the same world with the binder constant for the connection, the
  shape of draft-fossati-seat-early-attestation-07 Section 5.1. The check on `hatls-chain.pv`.
- `results/proverif-20260921.txt` — the output of the first two, from ProVerif 2.05.
- `results/proverif-20260922.txt` — the output of all four, from ProVerif 2.05, with the attack
  trace the prover reconstructed for the constant binder.

## What was proved

Against a Dolev-Yao attacker, with the identity key handed to the attacker in the clear and
unboundedly many parallel sessions:

| Query | Result |
|---|---|
| anything the mandate accepts was attested **by that instance, for the exporter the mandate itself derived** | true |
| anything the mandate accepts was attested by the **enrolled** instance | true |
| a step accepted under one **session context** was produced under it | true |
| the honest run is reachable | reachable |

The first three are the relay, re-hosting and session-separation properties the implementation
claims. The fourth matters as much as the others: a protocol nobody can complete proves everything
vacuously, so the model is checked to be usable before its guarantees mean anything.

## Order: what `hatls-chain.pv` adds, and what it was checked against

`hatls.pv` has one link per session and no counter, so it says nothing about order. The
implementation's claim — measured on real silicon in `evidence/reattest-20260922T133416Z/` —
is stronger: a link is not merely fresh, it is *positioned*, so the link from position 0 cannot
be accepted at position 1 and links cannot be skipped or reordered. That claim is now proved.

The chain is modelled as the code walks it (`tools/guest_probe.py`, `Mandate._appraise` steps
3–4): `p0 = link(exporter, intra_link, c0)`, `p(n+1) = link(exporter, p(n), c(n+1))`; the mandate
accepts position 0 only at counter 0 chained from `intra_link`, and position n+1 only at counter
n+1 chained from the link *it accepted* at n. Its state is sequential composition.

The attacker is deliberately stronger than in `hatls.pv`: besides the stolen identity key, the
thief's own TEE signs anything the thief asks (a thief controls the software in its own guest),
and the thief is the TLS peer of some sessions with the honest guest and of some with the mandate,
learning those sessions' exporter and context — which is what a relay actually is.

| Query, `hatls-chain.pv` | Result |
|---|---|
| a link accepted at position n was attested by the enrolled instance, for the mandate's own exporter, in this session, **at position n, and before acceptance** | true |
| the same, injectively: no accepted link is backed by an attestation already used | true |
| the accepting instance is the enrolled one | true |
| the honest three-link run is reachable | reachable |

In ProVerif `event(A) ==> event(B)` means every A is preceded by a B in the trace, so the first
row is a statement about order, not only about values.

`hatls-constant-binder.pv` is the identical world, attacker and queries with one change: the
binder is derived once per connection and never changes — the shape of Section 5.1 of
draft-fossati-seat-early-attestation-07. Section 8.4 of that draft says in prose what should then
happen: an attester "could resend Evidence generated earlier in the connection in response to a
later reattestation request, since the binder still matches". The prover finds exactly that:

```
event(AcceptedAt(...,c1,...)) ==> event(AttestedAt(...,c1,...))    is false
```

with a trace in which the Evidence emitted at position 0 is accepted, unchanged, at position 1,
in the same session and under the same exporter (`results/proverif-20260922.txt`). That is the
attack measured on hardware, found by the prover; the two files differ only in the binder, so
the proof in `hatls-chain.pv` is not vacuous, and the property it proves is the one the constant
binder lacks.

Scope, as for the hardware run: the constant binder here is derived from the session context,
not from the ClientHello..ServerHello transcript the draft specifies. The property under test is
constancy, which both share, and the 8.4 defect follows from constancy alone.

## Why the second file exists

A proof is worth exactly what its model is worth. A model with mis-stated events, too weak an
attacker, or an unreachable mandate returns "true" for everything and means nothing.

So `hatls-relay-defect.pv` is the identical model with one change: the mandate takes the exporter
and session context from the peer's message instead of deriving them from its own TLS session —
exactly what the shipped client did before the 21 September 2026 audit — and the attester publishes
them, exactly as the guest probe did. ProVerif finds the attack:

```
event(AcceptedInSession(t,sc)) ==> event(AttestedInSession(t,sc))    is false
```

The other two queries stay **true** in the broken model, and that is not a weakness of the check —
it is the shape of the real defect. A relay forwards genuine evidence from the genuine enrolled
chip, so the instance binding holds perfectly; what breaks is only the binding to *this* session.
The model localises the failure to precisely the property the implementation had lost.

## What the model assumes, and does not cover

Assumed: a Dolev-Yao attacker; the identity key is public, because "the key was stolen" is the
premise of the design and not a corner case; a TEE instance is a signing key the attacker does not
have, which is the one thing the hardware is asked to provide; and the TLS exporter is a fresh
secret shared by exactly the two endpoints of one session, which is what RFC 8446 gives.

Not covered: TLS itself, the transfer grant, revocation, the ledger and its receipts, and the
hardware-witnessed head. Those are authorisation and accountability rather than the binder, and
claiming them here would be overreach.

## Reproducing

ProVerif is not in Ubuntu's archives; it builds from the official source with the system OCaml:

```bash
sudo apt-get install -y ocaml ocaml-findlib build-essential
curl -sL -o pv.tar.gz https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf pv.tar.gz && cd proverif2.05 && ./build
./proverif ../hatls.pv
./proverif ../hatls-relay-defect.pv
./proverif ../hatls-chain.pv
./proverif ../hatls-constant-binder.pv
```

Both runs were on a throwaway cloud VM (Ubuntu 24.04, e2-medium) rather than a workstation, and
the VM was deleted afterwards. Each of the four models finishes in under a second (measured: 0.02–0.05 s).
