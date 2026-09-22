"""The four readings of "Hash(ClientHello...ServerHello)" under HelloRetryRequest never coincide.

In-process TLS 1.3 handshakes (stdlib ssl, memory BIOs), no network. See examples/hrr_binder.py.
"""
import os, sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"))
from hrr_binder import temp_identity, handshake, four_readings, plaintext_handshake_messages
from hatls.transcript import suite_hash, HRR_RANDOM, transcript_ch_sh

@pytest.fixture(scope="module")
def ident():
    return temp_identity()

def test_a_restricted_server_produces_a_hello_retry_request(ident):
    d, _ = ident
    c2s, s2c, _ = handshake(d)
    assert any(m[6:38] == HRR_RANDOM for m in plaintext_handshake_messages(s2c))
    assert sum(1 for m in plaintext_handshake_messages(c2s) if m[0] == 0x01) == 2

def test_the_four_readings_give_four_binders_every_time(ident):
    d, spki = ident
    for _ in range(20):
        c2s, s2c, suite = handshake(d)
        b, _ = four_readings(c2s, s2c, spki, suite_hash(suite))
        assert len(set(b.values())) == 4

def test_no_retry_when_the_groups_agree(ident):
    d, _ = ident
    _, s2c, _ = handshake(d, server_curve="X25519")
    assert not any(m[6:38] == HRR_RANDOM for m in plaintext_handshake_messages(s2c))

def test_hatls_transcript_helper_refuses_a_retry_handshake(ident):
    """hatls/transcript.py does not guess: on a HelloRetryRequest handshake it raises."""
    d, _ = ident
    c2s, s2c, _ = handshake(d)
    with pytest.raises(ValueError, match="HelloRetryRequest"):
        transcript_ch_sh(c2s, s2c)
