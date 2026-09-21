# Audit of v0.1 — every defect, how it was found, what changed

*21 September 2026.* v0.1 of this repository was published with hardware results and announced to
the IETF RATS list. It was then reviewed against its own claims. The review found defects that
defeated guarantees the README asserted. This file records all of them, because a protocol whose
failures are hidden is worth less than one whose failures are written down.

Each finding was reproduced before it was believed, and each fix is guarded by a test that fails
against the old code.

---

## 1. A relay was accepted (critical)

**The claim.** "Relay a genuine session → exporter binding → detected."

**What was true.** The mandate was right: given the verifier's own exporter it rejected a relayed
link, and `test_relay_blocked` genuinely proved that. But the shipped hardware client
(`examples/client_mandate.py`) did this:

```python
exp = bytes.fromhex(blob["exporter"])      # the exporter, taken from the peer's own message
```

It also ran with `CERT_NONE`, took the identity key from the same JSON, and invented the
transcript as `sha384("hatls-hw-run-" + timestamp)`. A relay holding the stolen TLS key forwards
all of those unchanged, so every check passed and the relay was accepted.

The root cause is mundane: Python's stdlib `ssl` module has no `export_keying_material`, so there
was no way to derive an exporter locally without switching TLS library. The path of least
resistance was to read the peer's value — which is exactly the value that proves nothing.

**Reproduced.** Feeding the mandate the peer-supplied exporter: `accepted=True`. Feeding it a
locally derived one: `accepted=False`.

**Fixed.** `hatls/client.py` derives the exporter and the session context from its own connection
and reads the identity key out of the certificate the peer proved possession of in the handshake.
The guest no longer sends the exporter or the key at all, and no longer accepts a transcript from
the client: both ends derive the session context independently.

**Guarded by.** `examples/relay_demo.py` and `tests/test_relay_e2e.py` — three real TLS 1.3
endpoints on localhost, with a relay that holds the genuine key and forwards genuine hardware
evidence. Direct accepted, relay rejected. No cloud needed.

**Note.** This is the same class of defect as session misbinding in published attestation
CVEs. Ours was in the reference client rather than the protocol, which changes the fix and not
the seriousness.

---

## 2. Enrolment proved nothing about the key (critical)

**The claim.** "Enrolment: the chip signs that this key was born on me."

**What was true.** The enrolment report covered `SHA-512(nonce || CSR)` where the CSR was the
constant `b"HATLS-TIK-enrolment-CSR"`. `Mandate.enroll()` never checked that the CSR carried the
key being enrolled, never demanded proof of possession, accepted a caller-supplied nonce, and
stored the binding last-write-wins. The link between "this key" and "this chip" was a dictionary
assignment.

**Reproduced.** An attacker who knows only the **public** key — it is printed in the victim's TLS
certificate — re-enrols that identity onto their own chip. The mandate then blocks the rightful
owner on its next message. No secret was needed at any point.

**Fixed.** Enrolment now requires a PKCS#10 CSR that carries exactly the key being enrolled and is
self-signed by its private half (the CSR *is* the proof of possession), covered by a report over a
nonce **the mandate itself issued** and has not spent, from a platform that exposes an anchor. It
is first-write-wins; re-enrolment is an explicit operator action.

**Guarded by.** `test_enrolment_hijack_refused`, `test_enrolment_requires_a_csr_carrying_that_key`,
`test_enrolment_requires_proof_of_possession`, `test_enrolment_nonce_cannot_be_replayed`.

---

## 3. An impostor could revoke its victim (critical)

**The claim.** Evidence on a second chip → "fork detected, identity revoked". The hardware log
showed `A-after → declined-revoked` and this was presented as success.

**What was true.** It is an availability attack. Anyone presenting a stolen key from any genuine
chip destroyed the victim's identity — including on the enrolment path, where the mandate already
*knew* which instance was legitimate and revoked the victim anyway.

**Fixed.** Rejection targets the presenter. With enrolment on record the impostor is refused and
the victim is untouched. Without enrolment the mandate cannot tell owner from thief, so it protects
the incumbent chain, records **contention**, and refuses to pick a winner. Revocation is an
explicit operator act (`Mandate.revoke`).

**Guarded by.** `test_impostor_cannot_revoke_the_victim`,
`test_revocation_is_an_explicit_operator_act`.

---

## 4. The instance anchor could be absent and still compare equal (critical)

**The claim.** "The chip is the non-copyable anchor: same identity must stay on the same chip."

**What was true.** The anchor is the SEV-SNP `CHIP_ID`. Under a shared-tenancy VLEK that field is
all zeros. The code compared `anchor != enrolled_anchor`; zero bytes are not `None`, so the
comparison ran and always succeeded. On such a platform every machine looked like every other one
and re-hosting was undetectable — **with no error raised anywhere**.

**Measured, on our own archive.** Six distinct AWS instances —
`i-02587934b18bc3016`, `i-036d8dbd13f29cba2`, `i-03dcf507880e1961e`, `i-0603037ab5b36aada`,
`i-0bf334666a8c4868c`, `i-0d7bec270b4f73618` — all report `CHIP_ID = 00…00`. Of 93 archived
reports, the 15 VLEK-signed ones carry a zero anchor and the 78 VCEK-signed ones do not.

Worse for a verifier author: in all 15, `MASK_CHIP_KEY` is **clear**. The platform hides the
identifier without setting the flag that announces it, so a verifier trusting the flag concludes
it has a real anchor and hands back 64 zero bytes as an identity.

**Fixed.** `snp_anchor()` returns `None` when the identifier is masked *or* zero, and
`Mandate(require_anchor=True)` — the default — fails closed. `require_anchor=False` lets a deployer
accept the downgrade knowingly and logs it: ordering and relay defence still hold there, re-host
detection does not.

**Guarded by.** `test_masked_anchor_cannot_be_enrolled`, `test_masked_anchor_fails_closed_on_present`,
`test_masked_anchor_downgrade_is_explicit_and_logged`, and `tests/test_snp_corpus.py`, which puts
19 real hardware reports under CI with no network.

**Answered since, and now implemented.** `CHIP_ID` answers "same silicon?", not "same instance?".
Measuring our archive gave the better claim: `REPORT_ID` is present on all three clouds including
where `CHIP_ID` is masked, is distinct across all six AWS instances and across guests sharing one
GCP socket, and is generated by the AMD-SP rather than supplied by the hypervisor (Firmware ABI
1.54, Table 62 lists every `SNP_LAUNCH_START` input and `REPORT_ID` is not among them). HATLS now
anchors identity on the instance claim and carries the chip separately as *place*. The remaining
open part is the equivalent claim on TDX and Nitro, and the fact that `REPORT_ID` migrates with a
guest, which puts a migration agent inside the trust boundary wherever migration is enabled.

---

## 5. Continuity was per identity, so parallel connections were impossible (significant)

**What was true.** Chain state was keyed by the identity key alone, so a second concurrent
connection from the same server forked the first. Worse, whether the counter was checked at all
depended on a `new_session` flag passed in **by the caller**.

**Fixed.** A step's chain is looked up by the session context the verifier derived from its own
TLS session. Parallel connections each keep their own ordered chain; a session's first link must be
counter 0 and a continuation must advance by exactly one. The flag is gone from the signature, and
a test asserts it stays gone. The identity ledger — anchor, enrolment, revocation, contention — is
still shared across sessions, which is what lets the mandate see a stolen key presented to a
different relying party.

**Guarded by.** `test_one_identity_can_hold_parallel_sessions`,
`test_a_session_must_start_at_counter_zero`,
`test_the_caller_cannot_assert_its_way_past_the_counter`.

---

## 6. The verifier checked a signature and called it verification (significant)

**What was true.** One signature check against a KDS-published key. Milan hardcoded; no
`POLICY` check, so a **DEBUG-enabled** guest — one whose memory the host may read, including the
key being attested — was accepted; no `MEASUREMENT`; no VCEK/VLEK distinction; and no chain to the
AMD root.

**Fixed.** Product read from the report, VLEK refused rather than mis-fetched, `POLICY.DEBUG`
refused, optional `MEASUREMENT` pin, and path validation to the AMD root with ARK as the only trust
anchor and an optional root-digest pin.

**A finding worth its own line.** Path validation goes through OpenSSL deliberately. AMD signs ASK
and ARK with RSASSA-PSS and encodes `trailerField=1` explicitly — that is the DEFAULT value, and
X.690 §11.5 forbids encoding a DEFAULT in DER. python-cryptography's strict ASN.1 parser therefore
**refuses to load the AMD certificate chain at all**:

```
ParseError { kind: EncodedDefault, location: [... "AlgorithmIdentifier::params",
             "RsaPssParameters::_trailer_field"] }
```

A verifier written against that library sees an exception where it expected a root. If it treats
that as "skip the chain", it silently falls back to trusting whatever key signed the report. We
suspect this is one reason chain validation is so often absent in attestation code. Confirmed
against the live KDS endpoint on 21 September 2026.

**Validated.** 93 archived reports parse with zero failures; full path validation to the AMD root
succeeds on three distinct live chips; a single flipped `MEASUREMENT` byte is rejected.

---

## 7. Documentation claimed more than the code delivered

- `GAP-ANALYSIS.md` said the first message under a stolen key passes, while `THREAT-MODEL.md` and
  the README said enrolment removes that ceiling. Both were dated the same day. Reconciled: with
  enrolment the impostor is refused on its first message; without it, the first presenter is
  accepted and a later second instance is flagged as contention.
- The README listed a **sealed key** as an implemented layer. It is not implemented in this
  repository — `scripts/launch.sh` deliberately ships one key to two guests, which is the
  stolen-key model being demonstrated. Now marked as designed, not implemented.
- The README quoted `0 false rejects / 500` with no script in the repository to produce it.
  `bench/benchmark.py` now does, and the numbers are re-measured against the fixed code.
- "Physical-insider window ≈ 8 ms" conflated the **beacon cadence** with the attacker's window.
  7.96 ms is how fast the chip can emit a fresh liveness beacon, which bounds detection
  resolution. While the key is in cleartext in guest memory, the window is the life of the process.
- "Unifies the two SEAT camps" overstated a real but narrower contribution. HATLS is a continuity
  layer that is post-handshake by nature: its Evidence binds the TLS exporter, which exists only
  after the handshake. The early binder is an input to the first link, not a second delivery
  channel. The README says so now.

---

## Still open

- The binder and the mandate are now machine-proved in ProVerif (see `formal/`), including a
  deliberately broken copy in which the prover finds the v0.1 relay — the check that the model is
  sensitive rather than agreeable. TLS itself, grants, revocation, the ledger and the witnessed
  head are outside that model.
- The early binder runs over a session context both endpoints derive independently, not over the
  true handshake transcript, which needs a TLS stack hook.
- Instance identity beyond `CHIP_ID`, across SEV-SNP / TDX / Nitro (see finding 4).
- Live migration to another socket still reads as a fork; the fix is a platform-signed migration
  statement the mandate accepts.
- Sealing the identity key to its chip.
- **The mandate is trusted and unmodelled.** Durability is now available — `FileStore` keeps the
  ledger across a restart, and `require_enrolment=True` turns a lost ledger into a refusal rather
  than a silent downgrade — but the mandate is still a single component: not replicated, issuing no
  receipts, and unauditable after the fact by anyone else. What a relying party may decide when the
  mandate is unavailable or lying remains unspecified.
- **Dispute resolution now exists, and brings its own key.** An identity may name a transfer
  authority at enrolment; only a single-use, time-bounded grant signed by it moves the identity.
  The mandate enforces rather than adjudicates. The new exposure is that authority key: lose it and
  the workload is stranded, steal it and the workload moves. No k-of-n, no authority recovery.
- **Cross-mandate divergence is now detectable, still not prevented — and this is not a federation.** One hardware report can carry
  several mandates' ledger heads at once, so their claims meet inside evidence neither controls;
  a mandate whose later history does not extend what the chip witnessed is caught. Preventing two
  mandates from admitting different instances needs consensus and is not attempted.
- **The identity is proved by possession, not by a CA.** Without `ca_file` the client runs
  `VERIFY_NONE` deliberately: TLS 1.3 CertificateVerify proves the peer holds the key, and the
  mandate decides whether that key is legitimate. Nothing here validates a PKI chain, and the
  documentation must keep saying so.
- **One vendor, one cloud, one generation.** The hardware evidence is GCP SEV-SNP Milan, two chips.
  The relay demonstration is a localhost relay against a real confidential VM — enough to show the
  defect is fixed, not enough to stand as a standard's evidence base.
- Contention policy: recording a dispute is the right primitive, but who resolves it, on what
  evidence, and in what time bound is unspecified.
