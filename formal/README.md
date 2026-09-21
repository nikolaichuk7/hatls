# Formal model

> **IN THE MODEL: the continuity binder and the mandate's appraisal of one step.**
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
- `results/proverif-20260921.txt` — the output of both, from ProVerif 2.05.

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
```

It was run on a throwaway cloud VM rather than a workstation, and the VM was deleted afterwards.
