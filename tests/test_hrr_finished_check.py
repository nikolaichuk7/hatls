"""After a HelloRetryRequest the stack's own transcript is the message_hash reading, and no other.

In-process TLS 1.3 handshakes (stdlib ssl, memory BIOs), no network. The Finished messages the
stack sent are recomputed over a transcript rebuilt from the captured handshake messages.
See examples/hrr_finished_check.py.
"""
import os, sys
import pytest
from cryptography.exceptions import InvalidTag
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"))
from hrr_finished_check import handshake, check, only_c, C
from hrr_binder import temp_identity

@pytest.fixture(scope="module")
def ident():
    return temp_identity()

def test_both_finished_verify_under_the_message_hash_reading_and_under_no_other(ident):
    d, _ = ident
    for _ in range(20):
        result = check(*handshake(d))
        assert len(result) == 4 and result[C] == (True, True)
        assert only_c(result)

def test_without_a_retry_the_plain_concatenation_verifies(ident):
    """The control: the checker decrypts and verifies an ordinary handshake, so a failure under a
    reading is a statement about the reading and not about the checker."""
    d, _ = ident
    assert check(*handshake(d, server_curve="X25519")) == {"CH || SH": (True, True)}

def test_a_wrong_secret_does_not_verify(ident):
    """The check is not vacuous: with the two handshake secrets swapped, decryption fails."""
    d, _ = ident
    c2s, s2c, suite, secrets = handshake(d)
    swapped = dict(secrets, SERVER_HANDSHAKE_TRAFFIC_SECRET=secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"],
                   CLIENT_HANDSHAKE_TRAFFIC_SECRET=secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"])
    with pytest.raises(InvalidTag):
        check(c2s, s2c, suite, swapped)
