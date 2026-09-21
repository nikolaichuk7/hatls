"""HATLS protocol tests.

The honest path is accepted; every attack in the playground is stopped; and the three defects the
21 Sep 2026 audit found stay fixed (see docs/AUDIT.md).
"""
import os, sys, hashlib, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr
from hatls.tee import MockTEE, mock_verifier

CHIP_A=(b"\xa2\xb2\x58\x0a"*16)[:64]; CHIP_B=(b"\x76\x10\x22\xd0"*16)[:64]; ZERO=bytes(64)

def _key():
    k=ec.generate_private_key(ec.SECP256R1())
    pub=k.public_key().public_bytes(serialization.Encoding.DER,
                                    serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pub, make_enrolment_csr(k)

TIK_PRIV, TIK, CSR = _key()

def _setup(chip=CHIP_A):
    tA=MockTEE(chip); tB=MockTEE(CHIP_B); v=mock_verifier({tA.pub.hex(), tB.pub.hex()})
    m=Mandate(v); n=m.challenge()
    ok,why=m.enroll(TIK, tA.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert ok, why
    return m, tA, tB

# ---------------- the original guarantees still hold ----------------
def test_honest_accepted():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e)); assert ok, why

def test_rehost_blocked():
    m,_,tB=_setup(); a=Attester(tB,TIK); e=os.urandom(32); t=os.urandom(48)
    ok,why=m.present(TIK,t,e,a.attest(t,e))
    assert not ok and "not enrolled" in why

def test_replay_blocked():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,e,a.attest(t,e)); s=a.attest(t,e); m.present(TIK,t,e,s)
    ok,_=m.present(TIK,t,e,s); assert not ok

def test_relay_blocked():
    m,tA,_=_setup(); a=Attester(tA,TIK); eg=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,eg,a.attest(t,eg))
    ok,_=m.present(TIK,t,os.urandom(32),a.attest(t,eg)); assert not ok

def test_splice_blocked():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    m.present(TIK,t,e,a.attest(t,e)); stolen=a.attest(t,e)
    ok,_=m.present(TIK,os.urandom(48),os.urandom(32),stolen); assert not ok

# ---------------- audit regressions: enrolment actually binds the key ----------------
def test_enrolment_hijack_refused():
    """An attacker knowing only the PUBLIC key must not be able to re-enrol it on his own chip."""
    m,tA,tB=_setup(); n=m.challenge()
    ok,why=m.enroll(TIK, tB.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert not ok and "already enrolled" in why
    a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    ok2,why2=m.present(TIK,t,e,a.attest(t,e))
    assert ok2, f"the rightful owner must remain usable, got: {why2}"

def test_enrolment_requires_a_csr_carrying_that_key():
    m,tA,_=_setup(); _,OTHER,OTHER_CSR=_key(); n=m.challenge()
    ok,why=m.enroll(OTHER, tA.report(hashlib.sha512(n+CSR).digest()), n, CSR)
    assert not ok and "does not carry" in why

def test_enrolment_requires_proof_of_possession():
    m,tA,_=_setup(); _,OTHER,_o=_key(); n=m.challenge()
    ok,why=m.enroll(OTHER, tA.report(hashlib.sha512(n+b"not-a-csr").digest()), n, b"not-a-csr")
    assert not ok and "unusable" in why

def test_enrolment_nonce_cannot_be_replayed():
    m,tA,_=_setup(); _,OTHER,OTHER_CSR=_key(); stale=os.urandom(32)
    ok,why=m.enroll(OTHER, tA.report(hashlib.sha512(stale+OTHER_CSR).digest()), stale, OTHER_CSR)
    assert not ok and "not issued" in why

# ---------------- the anchor must exist, and it must be the right claim ----------------
def test_a_platform_with_no_instance_claim_fails_closed():
    """No REPORT_ID means the instance question is unanswerable, whatever else is present."""
    z = MockTEE(CHIP_A, instance_id=ZERO[:32])
    m = Mandate(mock_verifier({z.pub.hex()}))
    a = Attester(z, TIK); c, e = os.urandom(48), os.urandom(32)
    ok, why = m.present(TIK, c, e, a.attest(c, e))
    assert not ok and "instance claim" in why

def test_a_masked_chip_no_longer_blinds_the_mandate():
    """THE AWS CASE. CHIP_ID is all zeros, as it is under a shared-tenancy VLEK, yet the two
    machines are still told apart -- because identity lives in REPORT_ID, not in the silicon.
    Anchored on CHIP_ID this was undetectable, with no error raised anywhere."""
    a1 = MockTEE(ZERO); a2 = MockTEE(ZERO)          # two AWS instances, no place claim at all
    m = Mandate(mock_verifier({a1.pub.hex(), a2.pub.hex()}))
    n = m.challenge()
    ok, why = m.enroll(TIK, a1.report(hashlib.sha512(n + CSR).digest()), n, CSR)
    assert ok, f"a platform with no silicon claim can still enrol an instance: {why}"
    c, e = os.urandom(48), os.urandom(32)
    ok2, why2 = m.present(TIK, c, e, Attester(a2, TIK).attest(c, e))
    assert not ok2 and "not enrolled" in why2, "the stolen key on the other AWS machine is caught"
    c, e = os.urandom(48), os.urandom(32)
    assert m.present(TIK, c, e, Attester(a1, TIK).attest(c, e))[0]

def test_two_guests_on_one_socket_are_told_apart():
    """The case a chip anchor cannot see: same silicon, different guest. In our own archive five
    GCP chips each carried between two and four distinct REPORT_IDs."""
    g1 = MockTEE(CHIP_A); g2 = MockTEE(CHIP_A)      # identical place, different instance
    assert g1.chip == g2.chip and g1.instance != g2.instance
    m = Mandate(mock_verifier({g1.pub.hex(), g2.pub.hex()}))
    n = m.challenge(); m.enroll(TIK, g1.report(hashlib.sha512(n + CSR).digest()), n, CSR)
    c, e = os.urandom(48), os.urandom(32)
    ok, why = m.present(TIK, c, e, Attester(g2, TIK).attest(c, e))
    assert not ok and "not enrolled" in why

def test_place_can_be_pinned_separately_when_a_deployment_wants_it():
    g = MockTEE(CHIP_A)
    m = Mandate(mock_verifier({g.pub.hex()}), require_place=True)
    n = m.challenge()
    assert m.enroll(TIK, g.report(hashlib.sha512(n + CSR).digest()), n, CSR)[0]
    c, e = os.urandom(48), os.urandom(32)
    assert m.present(TIK, c, e, Attester(g, TIK).attest(c, e))[0]

def test_requiring_a_place_refuses_a_platform_that_has_none():
    z = MockTEE(ZERO)
    m = Mandate(mock_verifier({z.pub.hex()}), require_place=True)
    n = m.challenge()
    ok, why = m.enroll(TIK, z.report(hashlib.sha512(n + CSR).digest()), n, CSR)
    assert not ok and "place claim" in why

# ---------------- audit regressions: an impostor cannot revoke the victim ----------------
def test_impostor_cannot_revoke_the_victim():
    m,tA,tB=_setup(); t=os.urandom(48)
    victim=Attester(tA,TIK); ev=os.urandom(32)
    assert m.present(TIK,t,ev,victim.attest(t,ev))[0]
    thief=Attester(tB,TIK); et=os.urandom(32)
    ok,_=m.present(TIK,t,et,thief.attest(t,et)); assert not ok
    ok2,why2=m.present(TIK,t,ev,victim.attest(t,ev))          # victim carries on
    assert ok2, f"victim must survive an impostor, got: {why2}"
    assert m.contention[TIK.hex()], "the dispute must still be recorded"

def test_revocation_is_an_explicit_operator_act():
    m,tA,_=_setup(); a=Attester(tA,TIK); e=os.urandom(32); t=os.urandom(48)
    assert m.present(TIK,t,e,a.attest(t,e))[0]
    m.revoke(TIK, reason="key disclosed in incident 42")
    ok,why=m.present(TIK,t,e,a.attest(t,e)); assert not ok and "revoked" in why

# ---------- audit regressions: continuity is per connection, the ledger is per identity ----------
def test_one_identity_can_hold_parallel_sessions():
    """Two concurrent TLS sessions from the same server. v0.1 kept one chain per identity, so the
    second connection forked the first; a pool of connections could not be attested at all."""
    m,tA,_=_setup()
    a1=Attester(tA,TIK); a2=Attester(tA,TIK)
    c1,e1 = os.urandom(48), os.urandom(32)
    c2,e2 = os.urandom(48), os.urandom(32)
    assert m.present(TIK,c1,e1,a1.attest(c1,e1))[0], "session 1 link 0"
    assert m.present(TIK,c2,e2,a2.attest(c2,e2))[0], "session 2 link 0"
    assert m.present(TIK,c1,e1,a1.attest(c1,e1))[0], "session 1 must continue after session 2 opened"
    assert m.present(TIK,c2,e2,a2.attest(c2,e2))[0], "session 2 link 1"

def test_a_session_must_start_at_counter_zero():
    m,tA,_=_setup(); a=Attester(tA,TIK); c,e = os.urandom(48), os.urandom(32)
    a.counter=5                                   # a presenter that claims to be mid-chain
    ok,why=m.present(TIK,c,e,a.attest(c,e)); assert not ok and "counter 0" in why

def test_the_caller_cannot_assert_its_way_past_the_counter():
    """There is no flag to pass: the chain a step belongs to is derived from the session context."""
    import inspect
    assert "new_session" not in inspect.signature(Mandate.present).parameters

# ---------- a named gap, pinned so it cannot be forgotten ----------
def test_restart_loses_enrolment_and_downgrades_the_guarantee():
    """The DEFAULT mandate keeps its ledger in memory, so a restart loses it.

    This asserts a weakness on purpose, and it is still the default behaviour by design: a store
    is a deployment decision, not something to fabricate silently. What changed is that there is
    now a way out of it, and that the silent part can be closed independently -- see
    tests/test_durability.py, `FileStore`, and `require_enrolment=True`."""
    m, tA, tB = _setup()
    assert TIK.hex() in m.enrolled
    restarted = Mandate(mock_verifier({tA.pub.hex(), tB.pub.hex()}))
    assert TIK.hex() not in restarted.enrolled
    thief = Attester(tB, TIK); c, e = os.urandom(48), os.urandom(32)
    ok, _ = restarted.present(TIK, c, e, thief.attest(c, e))
    assert ok, "documented gap: after a restart the impostor is no longer blocked on its first message"

def test_restart_also_invalidates_outstanding_challenges():
    m, tA, _ = _setup()
    nonce = m.challenge()
    restarted = Mandate(mock_verifier({tA.pub.hex()}))
    ok, why = restarted.enroll(TIK, tA.report(hashlib.sha512(nonce + CSR).digest()), nonce, CSR)
    assert not ok and "not issued" in why

# ---------- the mandate must state the guarantee it is actually running ----------
def test_the_first_log_entry_names_the_mode():
    """Defaults are soft on purpose. A reader of the log must not have to guess which."""
    m, _, _ = _setup()
    assert m.log[0][0] == "mandate-mode"
    assert m.log[0][1] == "in-process" and m.log[0][2] == "enrolment-optional"

def test_the_mode_line_reports_a_durable_store_and_a_required_enrolment():
    import tempfile, shutil
    from hatls.store import FileStore
    d = tempfile.mkdtemp(prefix="hatls-mode-")
    try:
        m = Mandate(mock_verifier(set()), store=FileStore(d), require_enrolment=True)
        assert m.log[0] == ("mandate-mode", "durable", "enrolment-required", "anchor-required")
    finally:
        shutil.rmtree(d, ignore_errors=True)
