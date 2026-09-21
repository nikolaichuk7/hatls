# Contributing to HATLS

HATLS is a research prototype and contributions are welcome, especially:

- **New attacks.** Add a function to `examples/attack.py`, open a PR, and say whether it gets
  through. Breaking the protocol is the most useful contribution.
- **New hardware.** Backends for AWS Nitro, Azure, or Intel TDX in `hatls/tee.py` (same interface
  as `SevSnpTEE`). The mandate logic is TEE-agnostic and should not change.
- **Measurements.** Reproduce a run on your own confidential VM and attach the evidence.

## Ground rules

- Every claim in a doc or the README must be reproducible from a script in the repo.
- No secrets in commits (keys, tokens). `.gitignore` covers the obvious ones; check your diff.
- Keep the honest-limits sections honest. If a change narrows or widens what is proven, update them.

## Development

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/
PYTHONPATH=. python3 examples/attack.py
```
