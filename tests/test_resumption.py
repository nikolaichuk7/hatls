"""A resumed TLS 1.3 handshake carries no Certificate message. Runs examples/resumption.sh when
an openssl 3.x binary is on PATH; skipped otherwise (the script is the reproduction either way)."""
import os, shutil, subprocess, re, socket
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl binary not on PATH")
def test_resumed_handshake_has_no_certificate_message():
    ver = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    if not re.search(r"OpenSSL 3\.", ver): pytest.skip(f"needs OpenSSL 3.x, have {ver.strip()}")
    out = subprocess.run(["bash", os.path.join(ROOT, "examples", "resumption.sh"), str(_free_port())],
                         capture_output=True, text=True, timeout=60).stdout
    assert "Reused, TLSv1.3" in out, out
    assert "Early data was accepted" in out, out
    assert re.search(r"connection 1 \(full\):\s+1", out), out
    assert re.search(r"connection 2 \(resumed\):\s+0", out), out
