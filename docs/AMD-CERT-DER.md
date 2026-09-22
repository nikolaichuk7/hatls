# AMD's certificate chain is not DER

> Pinned in `tests/test_amd_cert_der.py` on the public certificates in `evidence/amd-certs/`
> (fetched from AMD's KDS: `ARK-Milan`, `SEV-Milan` (ASK), `SEV-VLEK-Milan` (ASVK)).

The three RSASSA-PSS certificates above the VCEK/VLEK leaf encode the `trailerField` parameter
explicitly — `[3] INTEGER 1` — inside `RSASSA-PSS-params`. `trailerField` has a DEFAULT of 1, and
DER (X.690 §11.5) forbids encoding a value that equals its default. Consequences, measured here:

- `cryptography` (its Rust `asn1`) refuses all three: `ParseError { kind: EncodedDefault, location:
  [... "RsaPssParameters::_trailer_field"] }`. A verifier written on it cannot load AMD's chain.
- OpenSSL parses and validates them; its `asn1parse` shows the explicit field.
- The ECDSA VCEK leaf is unaffected.

For anyone building an endorsement-chain check for SEV-SNP in RATS or SEAT: the AMD root of
trust needs a tolerant parser, or the PSS parameters re-encoded before a strict one sees them.
This repository validates the chain with OpenSSL for that reason (`hatls/tee.py`). The root's
fingerprint pin (`ark_sha256`) is over the bytes AMD serves, so re-encoding must not be done
before pinning.
