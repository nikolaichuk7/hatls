"""End-to-end relay defence over real TLS 1.3 on localhost.

This is the regression guard for the v0.1 defect where the verifier read the exporter out of the
peer's message: a relay holding the stolen TLS key then passed. The demo asserts both directions,
so a future change that reintroduces wire-supplied binding values fails CI.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def test_relay_is_rejected_and_honest_client_is_not():
    from examples import relay_demo
    assert relay_demo.main() == 0
