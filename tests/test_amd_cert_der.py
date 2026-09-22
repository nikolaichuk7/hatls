"""AMD's ASK/ASVK/ARK certificates encode the RSASSA-PSS trailerField default explicitly, which
DER forbids (X.690 11.5). The bytes are the fact; what a parser does with them is the parser's
choice, and it changed: python-cryptography <= 42 refused the AMD root chain outright
(EncodedDefault), 43.0 and later tolerate it. Both behaviours are pinned here on the public
certificates in evidence/amd-certs/ (fetched from AMD's KDS), so the boundary stays recorded."""
import os, glob, subprocess, shutil
import pytest
import cryptography
from cryptography import x509

CERTS = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "evidence", "amd-certs", "*.der")))
MAJOR = int(cryptography.__version__.split(".")[0])

def test_the_three_certificates_are_shipped():
    assert [os.path.basename(c) for c in CERTS] == ["Milan-ark.der", "Milan-ask.der", "Milan-asvk.der"]

@pytest.mark.skipif(shutil.which("openssl") is None, reason="no openssl binary")
def test_the_bytes_encode_the_default_trailer_field_explicitly():
    """Version-independent: the DER violation is in the certificates themselves."""
    for c in CERTS:
        out = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", c], capture_output=True, text=True).stdout
        assert "cont [ 3 ]" in out and "INTEGER           :01" in out, c

def test_python_cryptography_behaviour_by_version():
    """<= 42: refuses with EncodedDefault. >= 43: parses. Measured across 42.0.8 .. 50.0.1."""
    for c in CERTS:
        der = open(c, "rb").read()
        if MAJOR <= 42:
            with pytest.raises(ValueError, match="EncodedDefault"):
                x509.load_der_x509_certificate(der)
        else:
            x509.load_der_x509_certificate(der)

def test_the_leaf_vcek_is_fine_everywhere():
    cache = glob.glob(os.path.join(os.path.dirname(__file__), "..", "hatls", "vcek-cache", "*.der"))
    if not cache: pytest.skip("no VCEK cached locally")
    x509.load_der_x509_certificate(open(cache[0], "rb").read())
