# Release notes

## v0.3.0 — 22 September 2026

Everything below reproduces from a clone; hardware runs ship their raw reports under `evidence/`.

**Repaired.** The guest probe (`tools/guest_probe.py`) could not answer a connection from v0.2.0
onward — a comment appended in `0f51084` had swallowed the statement after its semicolon. Recorded
results were unaffected (all captured before that commit); reproducibility by anyone else was
not. `tests/test_guest_probe_agrees.py` now calls the probe's and the library's derivations and
compares bytes.

**Measured, on draft-fossati-seat-early-attestation-07.** Section 8.4 (stale Evidence accepted
at reattestation), with the draft's own Section 5.1.1 binder computed from the real
ClientHello..ServerHello transcript (`hatls/transcript.py`, checked against RFC 8448): the stale
report is accepted; with the chain it is refused (`evidence/reattest-20260922T140735Z/`).
HelloRetryRequest gives four readings of "Hash(ClientHello...ServerHello)" and four binders,
200 of 200 (`examples/hrr_binder.py`). A resumed handshake has no Certificate message to carry
the extension (`examples/resumption.sh`).

**Proved.** `formal/hatls-chain.pv`: a link accepted at position *n* was attested at position
*n*, before acceptance, injectively, against a thief whose TEE signs anything and who is the TLS
peer of both ends. `formal/hatls-constant-binder.pv`: the same queries with a constant binder,
and ProVerif finds the Section 8.4 trace. Order is no longer a claim resting on tests.

**Measured, on silicon.** Signature malleability of SEV-SNP reports (75 of 75 conjugates pass
the full chain-validating verifier; enforcing low-S would reject 42 of 87 genuine reports) and
TDX quotes (3 of 3). Instance versus place versus class on 87 reports from two clouds: VCEK names
the chip, VLEK the region, `REPORT_ID` the instance, `CHIP_ID` all-zero on AWS while the report's
own flag says otherwise. TDX: two TDs from one image differ only in the host's `MROWNER` — and a
TD can extend RTMR3 once at boot and give itself a hardware-measured instance identity, which
`tdx_anchor` now reads. Runtime cost: an SNP report 7.7 ms, but the host throttles a guest to
about ten per ten seconds; a TDX quote 38.9 ms, unthrottled in 100; first accepted link 318 ms
end to end across the Internet. Evidence size against the initial congestion window: SEV-SNP
never crosses it, a TDX quote does with a long chain. AMD's ASK/ARK are not DER.

**Corrected, in our own claims.** Cost figures that came from other work replaced by
`examples/cost.py` on shipped reports. The 21 September liveness file already held a 10 237 ms
maximum beside the 7.96 ms median that had been quoted as a rate. Two counting slips in private
notes (one TDX quote of three; Certificate + CertificateVerify counted as two).

**Stated.** `docs/SEAT-GOALS.md`: draft-ietf-seat-use-cases-01 Section 4, goal by goal — three
not addressed (negotiation, the Passport model, privacy), two partial, the rest with the proof or
measurement that backs them.

New: `hatls/transcript.py`, `tdx_anchor`, ten example scripts, 74 tests (229 total). CI now runs
once per push. Both ends still derive every binding value from their own side of the session;
nothing that binds is read from the wire.

## v0.2.2 — 21 September 2026

See the repository history for v0.1 → v0.2.2: the audit that found the relay defect, the instance
anchor, enrolment with proof of possession, owner-authorised transfer, receipts and the witnessed
head, and the first hardware runs on GCP and AWS.
