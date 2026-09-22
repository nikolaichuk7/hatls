"""The guest probe must compute the SAME bytes as the library it is verified against.

The probe is a standalone script: it is copied into a confidential VM and runs there with no
access to `hatls/`, so its derivations are a hand-written second implementation. Nothing but a
test keeps the two in step, and a drift between them is invisible locally -- it only shows up as
a rejected link after someone has booted real hardware and paid for it.

This caught a real defect. In commit 0f51084 the probe's HKDF label was changed and a comment was
appended to the same line, swallowing the `info=...` assignment that followed a semicolon. The
file still compiled; `hkdf_expand_label` raised NameError on first use. Every release from v0.2.0
shipped a guest probe that could not answer a single connection, while the README invited readers
to clone it and run it on their own confidential VM. Import alone would not have caught it, so
these tests call the functions.
"""
import os, hashlib, importlib.util
import pytest
from hatls import protocol

_PROBE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "guest_probe.py")

def _load():
    spec = importlib.util.spec_from_file_location("guest_probe", _PROBE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # module level only; main() is behind __main__
    return mod

probe = _load()

SECRET = bytes(range(48))
CTX    = b"context bytes for the derivation"

def test_the_probe_hkdf_matches_the_library():
    for n in (32, 48):
        for label in (b"attestation base", b"attestation", b"continuity"):
            assert probe.hkdf_expand_label(SECRET, label, CTX, n) == \
                   protocol._hkdf_expand_label(SECRET, label, CTX, n), (label, n)

def test_the_probe_label_space_matches_the_library():
    # a drifted prefix would make every link disagree, on hardware only.
    assert probe.hkdf_expand_label(SECRET, b"x", CTX, 32) == protocol._hkdf_expand_label(SECRET, b"x", CTX, 32)

def test_the_probe_first_link_matches_the_library():
    sc, tik = bytes(48), b"\x30\x59" + bytes(89)
    assert probe.intra_link(sc, tik) == protocol.intra_link(sc, tik)

def test_the_probe_chain_matches_the_library():
    exp, prev = bytes(32), bytes(32)
    for counter in range(4):
        got  = probe.post_link(exp, prev, counter)
        want = protocol.post_link(exp, prev, counter)
        assert got == want, counter
        prev = got

def test_the_probe_report_data_matches_the_library():
    link = bytes(range(32))
    assert probe.report_data_for(link) == protocol.report_data_for(link)
    head = hashlib.sha256(b"a ledger head").digest()
    assert probe.report_data_for(link, head) == protocol.report_data_for(link, head)

def test_a_full_chain_agrees_end_to_end():
    """What the hardware run actually exercises: first link, then three chained links."""
    sc, tik, exp = bytes(48), b"\x30\x59" + bytes(89), bytes(32)
    p_prev = probe.intra_link(sc, tik)
    l_prev = protocol.intra_link(sc, tik)
    assert p_prev == l_prev
    for counter in range(3):
        p = probe.post_link(exp, p_prev if counter else probe.intra_link(sc, tik), counter)
        l = protocol.post_link(exp, l_prev if counter else protocol.intra_link(sc, tik), counter)
        assert probe.report_data_for(p) == protocol.report_data_for(l), counter
        p_prev, l_prev = p, l
