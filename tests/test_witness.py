"""Hardware-witnessed ledger heads: the one leverage a relying party has over the authority.

A signed log makes the mandate's decisions non-repudiable, but the head is still the mandate's own
word. It can sign two histories and each looks perfectly well-formed on its own. Carrying the head
into a report signed by a chip the mandate does not control changes that: the report says what the
mandate claimed at that moment, and the mandate cannot mint a different one.
"""
import os, sys, hashlib, base64, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr, report_data_for
from hatls.tee import MockTEE, mock_verifier
from hatls import receipt as R

CHIP_A = (b"\xa2\xb2\x58\x0a" * 16)[:64]
CHIP_B = (b"\x76\x10\x22\xd0" * 16)[:64]

def _key():
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
KEY, TIK = _key(); CSR = make_enrolment_csr(KEY)

def _mandate(**kw):
    tA, tB = MockTEE(CHIP_A), MockTEE(CHIP_B)
    m = Mandate(mock_verifier({tA.pub.hex(), tB.pub.hex()}), **kw)
    n = m.challenge()
    assert m.enroll(TIK, tA.report(hashlib.sha512(n + CSR).digest()), n, CSR)[0]
    return m, tA, tB

def _attest_with_head(m, tee):
    """What a relying party does: take the head, hand it over, let the chip sign across it."""
    head = m.head_for_attestation()
    c, e = os.urandom(48), os.urandom(32)
    msg = Attester(tee, TIK).attest(c, e, head=head)
    return head, c, e, msg

# ---------------- the binding works ----------------
def test_a_witnessed_attestation_is_accepted():
    m, tA, _ = _mandate()
    head, c, e, msg = _attest_with_head(m, tA)
    ok, why = m.present(TIK, c, e, msg, head=head)
    assert ok, why
    assert msg["head"] == head.hex()

def test_the_binder_differs_with_and_without_a_head():
    link = os.urandom(32); head = os.urandom(32)
    assert report_data_for(link) != report_data_for(link, head)

def test_a_report_bound_to_one_head_does_not_verify_against_another():
    """The substitution an auditor is looking for."""
    m, tA, _ = _mandate()
    head, c, e, msg = _attest_with_head(m, tA)
    other = os.urandom(32)
    assert report_data_for(bytes.fromhex(msg["post_link"]), head) != \
           report_data_for(bytes.fromhex(msg["post_link"]), other)

def test_a_head_this_log_never_had_is_refused():
    m, tA, _ = _mandate()
    bogus = os.urandom(32)
    c, e = os.urandom(48), os.urandom(32)
    msg = Attester(tA, TIK).attest(c, e, head=bogus)
    ok, why = m.present(TIK, c, e, msg, head=bogus)
    assert not ok and "not one this log had" in why

def test_a_head_is_remembered_across_its_whole_history():
    m, tA, _ = _mandate()
    early = m.head_for_attestation()
    for _ in range(4):
        h, c, e, msg = _attest_with_head(m, tA)
        assert m.present(TIK, c, e, msg, head=h)[0]
    assert m.knows_head(early), "a mandate must still account for the heads it served earlier"

# ---------------- the point of the exercise ----------------
def test_a_hardware_report_pins_the_history_the_mandate_served():
    """The mandate serves head H, a chip signs across it, and the mandate then adopts a history
    that never contained H. The report is what proves it did both."""
    m, tA, _ = _mandate()
    head, c, e, msg = _attest_with_head(m, tA)
    assert m.present(TIK, c, e, msg, head=head)[0]
    branch_a = m.sth()

    # the mandate rewrites its past into a history that never had that head
    m.merkle.entries = [R.make_entry("present", TIK, True, "a different history", seq=0)]
    m._roots = {m.merkle.head().hex(): 1}
    branch_b = m.sth()

    caught, why = R.is_equivocation(m.public_key, branch_a, branch_b)
    assert caught, why
    # and independently of the two signatures, the chip's report still names the original head
    assert bytes.fromhex(msg["head"]) == head
    assert not m.knows_head(head), "the rewritten mandate cannot account for what the chip saw"

def test_an_auditor_needs_only_the_report_and_the_claim():
    """No access to the mandate: recomputing REPORT_DATA is the whole check."""
    m, tA, _ = _mandate()
    head, c, e, msg = _attest_with_head(m, tA)
    assert m.present(TIK, c, e, msg, head=head)[0]
    claimed_link = bytes.fromhex(msg["post_link"])
    signed_over = bytes.fromhex(msg["evidence"]["report_data"])
    assert signed_over == report_data_for(claimed_link, head)
    assert signed_over != report_data_for(claimed_link, os.urandom(32))

def test_witnessing_is_optional_and_off_by_default():
    m, tA, _ = _mandate()
    c, e = os.urandom(48), os.urandom(32)
    msg = Attester(tA, TIK).attest(c, e)
    assert "head" not in msg
    assert m.present(TIK, c, e, msg)[0]
