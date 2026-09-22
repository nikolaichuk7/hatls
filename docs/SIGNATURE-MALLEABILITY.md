# Hardware attestation reports are signature-malleable

> **What this is:** a measurement on the genuine SEV-SNP reports and TDX quotes this repository
> ships. **What it is not:** a break of attestation, a forgery of claims, or a key recovery. The body
> of every report is untouched; only the encoding of an otherwise sound signature is at issue.
> Reproduce with `PYTHONPATH=. python3 examples/malleability.py`; the offline parts are pinned in
> `tests/test_malleability.py`.

## The property

ECDSA signatures come in pairs. If `(r, s)` verifies then `(r, n − s)` verifies too, under the same
key, over the same message. A signer can refuse to emit the second form (low-S canonicalisation,
the rule Bitcoin adopted as BIP-62 in 2014) and a verifier can refuse to accept it. Neither AMD's
Secure Processor nor Intel's Quoting Enclave does the first (measured below), and an ordinary
ECDSA verifier — OpenSSL's, which this repository uses and the flip was checked against — does not
do the second. So anyone holding one genuine report
can produce a second, byte-different, still-valid report of the same body — without any vendor key.

## Measured, on the reports in `evidence/`

87 distinct SEV-SNP reports from live guests: 71 on GCP (6 chips, VCEK-signed), 16 on AWS
shared tenancy (VLEK-signed). ECDSA P-384 over SHA-384; `r` and `s` at offset `0x2A0`, each a
72-byte little-endian field (SEV-SNP ABI, report signature).

| | |
|---|---|
| `s ≥ n/2` (high-S) | **42** of 87 |
| `s < n/2` (low-S) | 45 of 87 |
| distinct `r` | 87 of 87 — no nonce reuse, so no key leak |
| `r ≥ n/2` | 43 of 87 — uniform, as a healthy RNG gives |
| bodies appearing more than once | 2, both with **different** signatures |

A low-S canonicalising signer produces zero high-S; AMD produces them at the rate of an
unconstrained signer. A deterministic signer (RFC 6979) signs an identical body identically; AMD
does not. The firmware draws a fresh nonce every time and does not normalise `s`.

**The flip, through this repository's own verifier** (`hatls.tee.sevsnp_verifier`: signature,
VCEK → ASK → ARK chain from AMD's KDS, `REPORT_DATA`): of the 75 reports whose leaf certificate
is obtainable — VCEK by chip, or the VLEK the AWS run shipped — **75 originals verify and 75
flipped copies verify.** (12 VLEK reports from earlier AWS runs shipped no leaf and are counted
only in the structural rows.)

**Controls.** `s` replaced by `n − s + 1` — not the conjugate — fails. One bit of `REPORT_DATA`
flipped fails. The verifier rejects what is actually wrong.

**Intel TDX**, three Quote v4 quotes from three TDs (`evidence/tdx-quotes-20260911/`), QE
ECDSA-P256 over `header ‖ TD report` with the attestation key the quote itself carries: 1 of 3 is
high-S; all three verify in both forms. The QE does not canonicalise either. (Its certification by
QE report and PCK chain is the same for both forms and is not re-verified here.)

## The remedy that is not available

The standard fix is to reject high-S. A verifier that did so here would reject **42 of 87 genuine
AMD reports**. Against a signer that emits high-S itself, low-S enforcement is not a remedy; it is a
50 % outage. What remains is to identify evidence by what the signer committed to — the body — and
never by the bytes of the object or its signature.

## What it does and does not break

**Unaffected**, because the body is unchanged: nonces and epoch handles (RFC 9334 §10), attestation
binders over the transcript or exporter (draft-fossati-seat-early-attestation §5.1,
draft-fossati-seat-expat), relay and replay defences that check the binder, every claim, every
key. A relying party that appraises the body learns nothing false from a flipped copy.

**Affected**: any layer for which the identity of a piece of evidence is the hash of its bytes or
its signature. Concretely:

- a replay cache keyed by `hash(report)` sees the conjugate as new;
- a dedup or "already registered" rule keyed the same way passes it;
- a transparency log registering statements made "over the hash of a payload, rather than the full
  payload bytes" — the option draft-ietf-scitt-architecture gives — registers one report twice as
  two Artifacts, and neither the Issuer nor the Transparency Service can tell without parsing the
  body. SCITT leaves uniqueness to Registration Policies, so this is a consideration for those
  policies when the Artifact is a hardware report, not a defect in the architecture.

## Why HATLS is immune

The mandate's identity for a report is `REPORT_ID` and `CHIP_ID`, read from the body
(`hatls/tee.py: snp_anchor`); a flipped copy yields the same anchor
(`tests/test_malleability.py: test_a_flipped_copy_is_the_same_evidence_to_the_mandate`). Ledger
entries and receipts are over links and decisions, not report bytes. The attack playground's
"signature-forge / duplicate" case is this property exercised.

## Calibration

The class is old (BIP-62, 2014) and the mathematics is textbook. What is new, as far as we can
find, is the measurement on SEV-SNP and TDX silicon — that the vendors' signers are non-canonical,
that the flip passes a full chain-validating verifier, that the usual remedy is closed by the
vendors' own output — and the consequence for evidence-identity layers in RATS and SCITT. It is a
medium finding, stated as one.
