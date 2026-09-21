"""Who may create an identity here.

First-write-wins closed re-enrolment but not the race to be first. On a mandate that enrols
anybody, an attacker who arrives before the rightful owner simply owns the identity, and every
guarantee afterwards works perfectly on behalf of the wrong party.
"""
import os, sys, time, hashlib, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Attester, Mandate, make_enrolment_csr
from hatls.transfer import make_enrolment_authorisation, authority_public_bytes
from hatls.tee import MockTEE, mock_verifier

CHIP = (b"\xa2\xb2\x58\x0a" * 16)[:64]

def _key():
    k = ec.generate_private_key(ec.SECP256R1())
    return k, k.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)

KEY, TIK = _key(); CSR = make_enrolment_csr(KEY)
ISSUER, ISSUER_PUB = _key()
ROGUE, _ROGUE_PUB = _key()

def _m(**kw):
    tee = MockTEE(CHIP)
    return Mandate(mock_verifier({tee.pub.hex()}), **kw), tee

def _try_enrol(m, tee, auth=None, sig=None, nonce=None, tik=TIK, csr=CSR):
    n = nonce or m.challenge()
    return m.enroll(tik, tee.report(hashlib.sha512(n + csr).digest()), n, csr,
                    authorisation=auth, authorisation_sig=sig), n

def test_without_an_authority_anybody_may_enrol():
    m, tee = _m()
    (ok, why), _ = _try_enrol(m, tee)
    assert ok, why

def test_with_an_authority_an_unauthorised_enrolment_is_refused():
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    (ok, why), _ = _try_enrol(m, tee)
    assert not ok and "no authorisation was offered" in why

def test_an_authorised_enrolment_succeeds():
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    n = m.challenge()
    auth, sig = make_enrolment_authorisation(ISSUER, TIK, n)
    (ok, why), _ = _try_enrol(m, tee, auth, sig, nonce=n)
    assert ok, why

def test_an_authorisation_for_another_identity_is_refused():
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    _, other = _key()
    n = m.challenge()
    auth, sig = make_enrolment_authorisation(ISSUER, other, n)
    (ok, why), _ = _try_enrol(m, tee, auth, sig, nonce=n)
    assert not ok and "different identity" in why

def test_an_authorisation_cannot_be_replayed_against_another_challenge():
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    n1 = m.challenge()
    auth, sig = make_enrolment_authorisation(ISSUER, TIK, n1)
    n2 = m.challenge()
    (ok, why), _ = _try_enrol(m, tee, auth, sig, nonce=n2)
    assert not ok and "different challenge" in why

def test_an_expired_authorisation_is_refused():
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    n = m.challenge()
    auth, sig = make_enrolment_authorisation(ISSUER, TIK, n, valid_for=-1)
    (ok, why), _ = _try_enrol(m, tee, auth, sig, nonce=n)
    assert not ok and "validity window" in why

def test_an_authorisation_from_the_wrong_key_is_refused():
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    n = m.challenge()
    auth, sig = make_enrolment_authorisation(ROGUE, TIK, n)
    (ok, why), _ = _try_enrol(m, tee, auth, sig, nonce=n)
    assert not ok and "not signed by this mandate" in why

def test_a_tampered_authorisation_is_refused():
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    n = m.challenge()
    auth, sig = make_enrolment_authorisation(ISSUER, TIK, n)
    auth = dict(auth); auth["exp"] = auth["exp"] + 10_000
    (ok, why), _ = _try_enrol(m, tee, auth, sig, nonce=n)
    assert not ok and "not signed by this mandate" in why

def test_the_race_to_be_first_is_closed():
    """An attacker reaching the mandate before the owner no longer takes the identity."""
    m, tee = _m(enrolment_authority=ISSUER_PUB)
    (attacker_ok, _), _ = _try_enrol(m, tee)          # the attacker gets there first
    assert not attacker_ok
    n = m.challenge()
    auth, sig = make_enrolment_authorisation(ISSUER, TIK, n)
    (owner_ok, why), _ = _try_enrol(m, tee, auth, sig, nonce=n)
    assert owner_ok, why
    assert TIK.hex() in m.enrolled
