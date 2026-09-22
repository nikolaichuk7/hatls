# Against the SEAT working group's own list

draft-ietf-seat-use-cases-01, Section 4, opens:

> "This section provides a list of desirable security goals for designs that compose RA with
> secure channel protocols. Proposed protocol specifications should clearly state which of these
> security goals are fulfilled and explain how."

This is that statement for HATLS. One row per goal, in the draft's order and under the draft's
headings. Each row says what is done, where it is proved or measured **in this repository**, and
what is not done. Three goals are not addressed; those rows say so first.

| § | Goal | Status |
|---|---|---|
| 4.1 | Cryptographic binding to communication channel | **fulfilled** (post-handshake) |
| 4.2 | Compound authentication | partial |
| 4.3 | Cryptographic binding to machine identifier | **fulfilled** on SEV-SNP; on TDX with a guest-extended RTMR; fails closed otherwise |
| 4.4 | Attestation credential freshness | **fulfilled** (order and per-connection), no wall clock |
| 4.5 | Negotiation and capability discovery | **not addressed** |
| 4.6 | Attestation model flexibility | partial: Background Check only |
| 4.7 | Interaction with peer authentication | fulfilled structurally; PKI validation optional |
| 4.8 | Runtime attestation | **fulfilled** within a connection |
| 4.9 | Privacy preservation | **not addressed**; the mandate is a correlation point by design |
| 4.10 | Performance and efficiency | **fulfilled**, measured |

---

## 4.1 Cryptographic Binding to Communication Channel — fulfilled, post-handshake

*Goal:* Evidence bound to the specific (D)TLS connection, so Evidence from another connection
cannot be presented; the draft calls this "paramount" and cites CVE-2026-33697.

*How.* Every link is derived from an RFC 8446 exporter of **this** connection, under a label of
our own (`EXPERIMENTAL-hatls-continuity-exporter`), and the verifier derives that exporter from
**its own** side of the session (`hatls/client.py`); nothing that binds is read off the wire. The
identity the mandate appraises is the SubjectPublicKeyInfo of the certificate the handshake proved
possession of, not a field in the message. A relay that terminates TLS holds two connections with
two exporters and cannot make a link from one verify under the other.

*Proved.* `formal/hatls.pv`: anything accepted was attested for the exporter the mandate itself
derived, and under the same session context. `formal/hatls-chain.pv`: the same with the exporter
and session in every event, over three positions, against an attacker who is the TLS peer of
sessions with both ends. `formal/hatls-relay-defect.pv` shows the prover finding the v0.1 relay
when the exporter is taken from the peer.

*Measured.* A relay holding the guest's real stolen TLS key, forwarding genuine VCEK-signed
reports untouched, declined on link 0 on live SEV-SNP (`evidence/relay-hw-20260921T194244Z`,
`-20260922T133511Z`, `-20260922T140812Z`).

*Not done.* No binding **inside** the handshake. HATLS starts after the handshake completes; its
first link is derived from a second exporter (`EXPERIMENTAL-hatls-session-context`), not from the
ClientHello..ServerHello transcript. A deployment that needs Evidence before the handshake finishes
needs draft-fossati-seat-early-attestation underneath; the chain then continues from it.

## 4.2 Compound Authentication — partial

*Goal:* RA complements endpoint authentication rather than replacing it; a composition goal is
formalised in [ID-Crisis].

*How.* Authentication is TLS's: the identity key signs CertificateVerify, and HATLS never
re-implements that. Attestation is added on top and neither substitutes for the other: every link
binds `Hash(TIK)` through the first link; a valid identity key presented with Evidence from an
instance other than the enrolled one is refused on its first message (`Mandate._appraise` step
1c); Evidence without the identity key proves nothing, since the exporter and the key are both
inputs to the link.

*Proved.* `formal/hatls-chain.pv`, third query: anything accepted was attested by the **enrolled**
instance, with the identity key public to the attacker throughout.

*A structural note on the alternative.* The other route to "RA adds to authentication" is to have
the Evidence *assert* the key's provenance — non-exportable, generated inside — as
draft-fossati-seat-early-attestation §8.2 proposes via draft-reddy-rats-key-binding. On SEV-SNP
and TDX no report field carries such an attribute; the hardware AK signs a fixed structure whose
only guest-supplied bytes are `REPORT_DATA`, and the key-binding profile's own §8.3 rejects
carrying claims through that channel, requiring the AK to sign the claims set directly. So on
these platforms the assertion route needs a second, software attester inside the guest and trust
in its measurement; the observation route above needs only two firmware-written `REPORT_ID`s
(`docs/INSTANCE-IDENTITY.md`, "Who writes each field").

*Not done.* The composition property as [ID-Crisis] states it — a theorem over TLS 1.3 itself
with attestation composed in — is not stated as a query. TLS is outside our model; the exporter is
an assumption ("a fresh secret shared by exactly the two endpoints of one session"), not a derived
fact. What is proved is agreement on (identity, instance, exporter, session, position), which is
the shape of compound authentication, not a proof of the composition.

## 4.3 Cryptographic Binding to Machine Identifier — fulfilled on SEV-SNP, fails closed elsewhere

*Goal:* Evidence bound to "the identifier provided to the machine by the infrastructure provider",
against diversion.

*How.* The mandate binds authorisation to the **instance** the hardware reports — `REPORT_ID` on
SEV-SNP, the value the firmware generates at launch and holds for the guest's lifetime — and
enrols an identity to the instance it was born on (`hatls/tee.py: snp_anchor`,
`Mandate.enroll`). `CHIP_ID` is kept separately as *place*: silicon, not machine. Where no
usable instance claim exists the mandate refuses rather than degrades (`require_anchor`, on by
default; `Mandate` logs its mode as its first entry).

*Measured, in this repository.* 87 genuine SEV-SNP reports from live guests: 71 from GCP (6
distinct `CHIP_ID`, 14 distinct `REPORT_ID`: one chip served several instances over time), 16
from AWS shared tenancy (all VLEK-signed, **`CHIP_ID` all-zero in
every one**, 8 distinct `REPORT_ID`). On AWS the silicon identifier is unavailable and the
signing key is one per region, so `REPORT_ID` is the only claim that separates two machines
(`evidence/aws-anchor-*`, `docs/HARDWARE-RESULTS.md`). On Intel TDX, two TDs launched from one image
differ in exactly one TDREPORT field, `MROWNER` — which the host VMM supplies at TD
initialisation, so it is the word of the party that would do the re-hosting
(`evidence/tdx-claims-20260921T211425Z/verdict.json`). No firmware-issued instance claim exists
there; what exists is a register only the TD can write: extending RTMR3 once at boot with random
bytes gives two TDs from one image distinct, hardware-measured identities (measured,
`evidence/tdx-rtmr-20260922T160500Z/`), and `tdx_anchor` reads it, failing closed while RTMR3 is
zero. Quote signature verification against Intel's PCS is not implemented here.
`tests/test_snp_corpus.py` holds the rule: an all-zero `CHIP_ID` is never an identity.

*A note on wording.* The goal asks for an identifier "provided by the infrastructure provider".
`REPORT_ID` is provided by the firmware, not the provider, and we bind to it because it is what
the hardware attests: no provider-supplied identifier appears in any SEV-SNP report field in the
corpus: read at their ABI offsets across all 87 reports, `FAMILY_ID`, `IMAGE_ID` and `HOST_DATA`
each take exactly one value per cloud, across 14 instances on GCP and 8 on AWS. Whether a
firmware-issued instance identifier satisfies 4.3 as the working group means it is a question for
the group; we report what the chips give.

## 4.4 Attestation Credential Freshness — fulfilled for order and per-connection; no wall clock

*Goal:* the Relying Party can verify Evidence was freshly generated for this RA interaction.

*How.* Per connection: the first link is a function of this connection's exporter, so Evidence
from another connection does not verify. Per step: each later link is
`HKDF(exporter, prev_link ‖ counter)`, checked by the mandate against the link **it** accepted
last and the counter **it** expects (`Mandate._appraise` steps 3–4), so a link is not merely fresh,
it is *positioned*: link *n* cannot be accepted at *n+1*, nor skipped, nor reordered. Enrolment is
over a nonce the mandate issued (`Mandate.challenge`, `challenge_ttl`).

*Proved.* `formal/hatls-chain.pv`: acceptance at position *n* is preceded by attestation at
position *n* in that session, non-injectively and injectively. `formal/hatls-constant-binder.pv`
is the check: with a binder constant for the connection the prover finds the resend of position
0's Evidence at position 1 — the case draft-fossati-seat-early-attestation-07 Section 8.4 states
in prose and defers.

*Measured.* `evidence/reattest-20260922T140735Z`: with that draft's own Section 5.1.1 binder,
computed from the real transcript, two genuine reports in one connection carry byte-identical
`REPORT_DATA` and the stale one is accepted at reattestation; with the chain the same resend is
refused ("counter did not advance by one").

*A note on the transport's own options.* Of the reattestation mechanisms early-attestation §5.4
lists, Extended Key Update (Option 1) would give order without any chain, because each generation's
secrets derive from the previous one's; post-handshake authentication and CertificateUpdate would
not, because each exchange restarts from the handshake context (RFC 8446 §4.4). As of 22 September
2026 no implementation of draft-ietf-tls-extended-key-update is found in OpenSSL 3.6.4 (headers or
libssl) or in the sources of BoringSSL, wolfSSL, rustls or Go's crypto/tls (s2n, Mbed TLS and GnuTLS
not checked), so Option 1 has no running code to measure against.

*Not done.* No clock. The chain proves order and non-replay, not that a link was produced within
the last *T* seconds; a slow attester is indistinguishable from a prompt one. The resolution at
which a stalled chain is noticed is bounded not by the chip's 7.96 ms per report but by the host's
throttle on guest requests — about 10 reports per 10 s on GCP, so ~1 s (`docs/RUNTIME-COST.md`) —
and a deployment sets its cadence within that.

## 4.5 Negotiation and Capability Discovery — not addressed

*Goal:* a secure mechanism to discover RA support, Evidence formats and attestation models, with
graceful fallback.

HATLS has none, and this is deliberate rather than an omission: the layer sits above the
transport, and discovery of formats and models belongs to whichever transport carries the
Evidence (the `remoteAttestation` extension of early attestation, the `cmw_attestation`
extension of expat). Evidence in HATLS carries a `kind` tag (`sev-snp`, `tdx`, `mock`) that
identifies its content type; that is labelling, not negotiation. There is no negotiated
"attestation required" signal: a peer that never starts a chain simply has no continuity, and the
mandate's lack of state for it is visible to the Relying Party, but nothing authenticated says the
peer *should* have started one.

## 4.6 Attestation Model Flexibility — partial: Background Check only

*Goal:* support for both the Background Check and Passport models of RFC 9334.

The mandate is a Verifier and a Relying Party in one process: it appraises Evidence itself
(Background Check, with the Verifier co-located) and there is no separate Verifier endpoint. Its
signed receipts and log heads (`hatls/receipt.py`, `hatls/log.py`) let a third party check what
it decided — accountability after the fact — but the Passport flow, in which the Attester obtains
Attestation Results and presents them to a Relying Party, is not implemented. A deployment that
needs the Verifier offline from the Relying Party does not get it from this code.

## 4.7 Interaction with Peer Authentication — fulfilled structurally; PKI validation optional

*Goal:* RA alongside PKI-based authentication, two independent pillars.

The identity is an X.509 end-entity certificate proved in the TLS handshake; the mandate keys its
ledger on that certificate's SubjectPublicKeyInfo and takes it from the handshake, not from the
message. Enrolment is a real PKCS#10 request carrying that key, self-signed as proof of
possession over the mandate's nonce (`hatls/protocol.py: make_enrolment_csr`). Certificate-chain
validation is available (`HatlsClient(ca_file=...)`) and off by default: in every recorded run the
identity is self-signed, and trust in it comes from the mandate's ledger — enrolment, witnesses,
receipts — rather than from a CA. So the second pillar is present in structure and unexercised in
evidence; a deployment with a PKI turns it on.

## 4.8 Runtime Attestation — fulfilled within a connection

*Goal:* Evidence during the connection's lifetime, periodic or on demand; the draft says current
systems "do not achieve" a guarantee about state change and that static Evidence "is insufficient"
on long-lived connections.

*How.* The connection's lifetime is covered by an ordered chain of hardware reports, each a fresh
SEV-SNP report carrying the platform's claims at that moment — `MEASUREMENT`, policy, TCB — which
the verifier re-appraises at every link (`sevsnp_verifier(measurement=..., allow_debug=False)`).
The guest walks the chain at its cadence and the Relying Party asks for as many steps as it wants
(`steps` in the probe request), so both the periodic and the on-demand shapes of 4.8.1 are the same
mechanism. A change the chip reports is seen at the next link; a change it does not report is not
seen at all, which is the limit the draft itself states.

*Measured.* Chains of two and three links per session on live SEV-SNP throughout `evidence/`;
the ledger head bound into a link by the chip in `evidence/witness-hw-*`. Longer chains have not
been run on hardware; the mechanism does not change with length. What a link costs and how many a
guest may have: a SEV-SNP report is 7.7 ms but the host throttles a guest to about ten per ten
seconds on GCP; a TDX quote is 38.9 ms with no throttle seen in 100 (`docs/RUNTIME-COST.md`).
That is the cadence 4.8.1's "periodic" attestation actually has available.

*Not done.* Session resumption is not handled by HATLS and not tested. By construction a resumed
TLS session has a fresh exporter, so no chain can be inherited and a new one must start at counter
0 under a new session context; but HATLS neither forbids tickets nor 0-RTT, as expat does, and a
test of resumption has not been written. The TOCTOU window between two links is the cadence the
deployment chooses.

## 4.9 Privacy Preservation — not addressed; the mandate is a correlation point by design

*Goal:* no degradation of a standard secure connection's privacy; Evidence is a tracking vector;
minimise what a third-party Verifier learns.

The network learns nothing new: Evidence travels inside the TLS connection. The mandate learns
everything: at every link it sees the full report — `CHIP_ID`, `REPORT_ID`, `MEASUREMENT`, TCB —
and it records instance identifiers durably per identity (`hatls/store.py: FileStore`); its
receipts and federation bundles publish log heads to third parties. This is not incidental.
Detecting re-hosting *is* linking two observations of one identity across time and across
machines, which is the opposite of unlinkability, and the mandate is trusted with that data as
a matter of design. No privacy-preserving attestation technique is used. A deployment must treat
the mandate as it would treat a Verifier holding a complete history of every attester it has seen.

## 4.10 Performance and Efficiency — fulfilled, measured

*Goal:* no prohibitive latency; minimise extra round trips and large handshake payloads.

Nothing is added to the handshake: HATLS starts after it. Per link, measured here on the real
reports the repository ships (`examples/cost.py`): deriving a link is 2.5 µs; a full mandate step
on a mock chip is 1.2 ms, mostly the mock's ECDSA; appraising a genuine SEV-SNP report is 1.6 ms
warm, and cold it costs whatever AMD's KDS takes to serve the VCEK and chain that day (0.5 s and
7.4 s in two consecutive measurements), once per chip and TCB — the one cost every SEV-SNP design
pays and the chain does not add to. State at the Relying Party is the last link and a counter per
live connection, about 40 bytes, plus the per-identity ledger record. No round trip is added to
the handshake; after it, one request–response carries a batch of steps in the probe protocol, and
the mandate appraises each step in that batch independently. End to end across the Internet,
the first accepted link arrives 318 ms after SYN (median; `docs/RUNTIME-COST.md`). For the
intra-handshake alternative, the bytes are in `docs/EVIDENCE-SIZE.md`: SEV-SNP Evidence never
pushes a server's first flight past the initial congestion window; a TDX quote does, with a long
web-PKI chain and a post-quantum key share.

---

## What a reviewer should still ask

- 4.2: where is the composition theorem? Not here; TLS is outside the model.
- 4.3: is a firmware-issued instance identifier what the group means by "provided by the
  infrastructure provider"? And what anchors an instance on TDX, where we found nothing?
- 4.8: resumption is argued from construction, not tested.
- 4.9: the mandate's history of every attester is the price of detection. Is that acceptable in the
  deployments the group has in mind?
- 4.5, 4.6: absent, by choice; a transport underneath must supply them.
