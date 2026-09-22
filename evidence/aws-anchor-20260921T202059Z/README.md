# This run's captures are damaged. Kept on purpose.

The two "reports" in `probes.json` are 1200 bytes and invalid base64, not 1184-byte SEV-SNP
reports. They came through the EC2 serial console, which interleaved its own text into the
base64 stream; `b64decode` silently dropped whatever was not in its alphabet and produced
plausible bytes of the wrong length with a version field reading 5. That nearly became a reported
finding about a new AWS report format.

The transport was changed to numbered fixed-width chunks with a SHA-256 digest so that damage
fails loudly; every later run in `evidence/aws-anchor-*` carries genuine 1184-byte reports. This
directory stays as the record of how the capture path was found to be wrong. Nothing in it is used
by any test or measurement: `examples/malleability.py` and `examples/granularity.py` take only
1184-byte reports, and `tests/test_granularity.py` skips anything else.
