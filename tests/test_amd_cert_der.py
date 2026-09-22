"""AMD's ASK/ASVK/ARK certificates encode the RSASSA-PSS trailerField default explicitly, which
DER forbids (X.690 11.5). A strict parser rejects the AMD root chain; OpenSSL accepts it. Pinned on
the public certificates shipped in evidence/amd-certs/ (fetched from AMD's KDS)."""
import os, glob, subprocess, shutil
import pytest
from cryptography import x509

CERTS = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "evidence", "amd-certs", "*.der")))

def test_the_three_certificates_are_shipped():
    assert [os.path.basename(c) for c in CERTS] == ["Milan-ark.der", "Milan-ask.der", "Milan-asvk.der"]

def test_a_strict_der_parser_rejects_every_amd_chain_certificate():
    for c in CERTS:
        with pytest.raises(ValueError, match="EncodedDefault|trailer"):
            x509.load_der_x509_certificate(open(c, "rb").read())

@pytest.mark.skipif(shutil.which("openssl") is None, reason="no openssl binary")
def test_openssl_parses_them_and_shows_the_explicit_trailer_field():
    for c in CERTS:
        out = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", c], capture_output=True, text=True).stdout
        assert "cont [ 3 ]" in out and "INTEGER           :01" in out, c

def test_the_leaf_vcek_is_fine():
    """The defect is in the RSA-PSS intermediates and root; the ECDSA leaf parses strictly."""
    cache = glob.glob(os.path.join(os.path.dirname(__file__), "..", "hatls", "vcek-cache", "*.der"))
    if not cache: pytest.skip("no VCEK cached locally")
    x509.load_der_x509_certificate(open(cache[0], "rb").read())
