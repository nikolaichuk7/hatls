"""Signature malleability of the shipped hardware reports -- pinned, offline.

examples/malleability.py is the full measurement (it fetches VCEKs from AMD's KDS for the
chain check). These tests pin the parts that need no network, on the reports in evidence/, so
the finding cannot silently stop being true of the data this repository ships:

  * AMD's firmware emits high-S signatures (a canonicalising signer would emit none);
  * identical bodies carry different signatures (randomised, not RFC 6979);
  * for VLEK reports whose run shipped the leaf, the flipped signature verifies under that
    leaf and a wrong one does not;
  * every shipped TDX quote verifies under its in-quote attestation key in both forms.

And the property that makes HATLS immune: the mandate's identity for a report is read from
the body, so a flipped copy is the same evidence.
"""
import os, sys, base64, glob
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"))
from malleability import shipped_reports, rs, with_s, vlek_pem, N384, BODY
from hatls.tee import sevsnp_verifier, parse_snp, snp_anchor

REPS = shipped_reports()

def test_the_archive_is_present():
    assert len(REPS) >= 80

def test_amd_emits_high_s():
    hi = sum(1 for b in REPS if rs(b)[1] >= N384 // 2)
    assert hi > 0, "no high-S report: either AMD started canonicalising or the archive changed"
    assert hi < len(REPS)

def test_no_signature_is_out_of_range():
    for b in REPS:
        r, s = rs(b); assert 0 < r < N384 and 0 < s < N384

def test_no_nonce_is_repeated():
    rvals = [rs(b)[0] for b in REPS]
    assert len(set(rvals)) == len(rvals), "a repeated ECDSA nonce would leak the AMD key"

def test_identical_bodies_carry_different_signatures():
    by_body = {}
    for b in REPS: by_body.setdefault(b[:BODY], set()).add(b[BODY:])
    multi = [v for v in by_body.values() if len(v) > 1]
    assert multi, "no body appears twice in the archive"
    assert all(len(v) > 1 for v in multi)

def _vlek_with_leaf():
    return [(b, leaf) for b, (src, leaf) in REPS.items() if leaf and parse_snp(b)["signing_key"] == "VLEK"]

def test_flipped_vlek_reports_verify_and_wrong_ones_do_not():
    pairs = _vlek_with_leaf()
    assert pairs, "no VLEK report with a shipped leaf"
    verify = sevsnp_verifier(require_chain=False)          # the leaf is in evidence; no network
    for b, leaf in pairs:
        f = parse_snp(b); pem = vlek_pem(leaf)
        ev = lambda rep: {"kind": "sev-snp", "report": base64.b64encode(rep).decode(), "leaf_pem": pem}
        r, s = rs(b)
        assert verify(ev(b), f["report_data"])[0]
        assert verify(ev(with_s(b, N384 - s)), f["report_data"])[0]            # the conjugate
        assert not verify(ev(with_s(b, (N384 - s + 1) % N384)), f["report_data"])[0]
        assert not verify(ev(b[:0x50] + bytes([b[0x50] ^ 1]) + b[0x51:]), f["report_data"])[0]

def test_a_flipped_copy_is_the_same_evidence_to_the_mandate():
    for b in list(REPS)[:20]:
        r, s = rs(b)
        assert snp_anchor(parse_snp(b)) == snp_anchor(parse_snp(with_s(b, N384 - s)))

def test_tdx_quotes_verify_in_both_forms():
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    quotes = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "evidence", "tdx-quotes-*", "*.bin")))
    assert len(quotes) == 3
    high = 0
    for p in quotes:
        q = open(p, "rb").read(); signed = q[:632]; sd = q[636:]
        r = int.from_bytes(sd[:32], "big"); s = int.from_bytes(sd[32:64], "big")
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(sd[64:96], "big"), int.from_bytes(sd[96:128], "big"), ec.SECP256R1()).public_key()
        for ss, want in ((s, True), (N256 - s, True), ((N256 - s + 1) % N256, False)):
            try: pub.verify(utils.encode_dss_signature(r, ss), signed, ec.ECDSA(hashes.SHA256())); got = True
            except Exception: got = False
            assert got is want, (p, ss == s)
        high += s >= N256 // 2
    assert high >= 1, "no high-S TDX quote: Intel's QE would then be canonicalising"
