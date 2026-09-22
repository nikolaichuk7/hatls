# AMD's certificate chain is not DER

> Pinned in `tests/test_amd_cert_der.py` on the public certificates in `evidence/amd-certs/`
> (fetched from AMD's KDS: `ARK-Milan`, `SEV-Milan` (ASK), `SEV-VLEK-Milan` (ASVK)).

The three RSASSA-PSS certificates above the VCEK/VLEK leaf encode the `trailerField` parameter
explicitly — `[3] INTEGER 1` — inside `RSASSA-PSS-params`. `trailerField` has a DEFAULT of 1, and
DER (X.690 §11.5) forbids encoding a value that equals its default. Consequences, measured here:

- python-cryptography **through 42.x** refuses all three: `ParseError { kind: EncodedDefault,
  location: [... "RsaPssParameters::_trailer_field"] }`; a verifier on those versions cannot load
  AMD's chain. **From 43.0.0 (20 July 2024) it parses them** — measured across 42.0.8, 43.0.3,
  44.0.3, 45.0.7, 46.0.3, 47.0.0, 48.0.0, 49.0.0 and 50.0.1; the boundary is exactly 43.0.
- OpenSSL parses and validates them; its `asn1parse` shows the explicit field.
- The ECDSA VCEK leaf is unaffected on every version.

So the finding is narrower than "strict parsers reject": the certificates are not DER, one widely
used parser rejected them for years and now tolerates them, and any decoder that enforces X.690
§11.5 still will. Both behaviours are pinned in the test so the boundary stays on record.

For anyone building an endorsement-chain check for SEV-SNP in RATS or SEAT: the AMD root of
trust needs a tolerant parser, or the PSS parameters re-encoded before a strict one sees them.
This repository validates the chain with OpenSSL for that reason (`hatls/tee.py`). The root's
fingerprint pin (`ark_sha256`) is over the bytes AMD serves, so re-encoding must not be done
before pinning.
