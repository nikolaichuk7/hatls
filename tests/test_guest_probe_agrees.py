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

# ---- the draft-binder helpers the probe carries (copies of hatls/transcript.py) ----
from hatls import transcript as T

def test_the_probe_tls13_hkdf_matches_the_library_and_rfc8448():
    early = bytes.fromhex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    want  = bytes.fromhex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
    ctx = hashlib.sha256(b"").digest()
    assert probe.tls13_hkdf_expand_label(early, b"derived", ctx, 32, hashlib.sha256) == want
    for H, n in ((hashlib.sha256, 32), (hashlib.sha384, 48)):
        for label in (b"attestation base", b"attestation"):
            assert probe.tls13_hkdf_expand_label(SECRET[:n], label, CTX, n, H) == \
                   T.tls13_hkdf_expand_label(SECRET[:n], label, CTX, n, H)

def test_the_probe_draft_binder_matches_the_library():
    ch = b"\x01\x00\x00\x05hello"; sh = b"\x02\x00\x00\x05world"; spki = b"\x30\x59" + bytes(89)
    for H in (hashlib.sha256, hashlib.sha384):
        assert probe.draft_binder(ch, sh, spki, H) == T.draft_binder(ch, sh, spki, H)
        assert probe.binder_report_data(probe.draft_binder(ch, sh, spki, H)) == \
               T.binder_report_data(T.draft_binder(ch, sh, spki, H))

def test_the_probe_transcript_parsing_matches_the_library():
    def rec(t, b): return bytes([t, 3, 3]) + len(b).to_bytes(2, "big") + b
    def hs(t, b):  return bytes([t]) + len(b).to_bytes(3, "big") + b
    ch = hs(0x01, bytes(range(120))); sh = hs(0x02, b"\x03\x03" + bytes(32) + b"\x00" * 20)
    c2s = rec(0x16, ch[:40]) + rec(0x16, ch[40:]) + rec(0x14, b"\x01")
    s2c = rec(0x16, sh) + rec(0x14, b"\x01") + rec(0x17, b"encrypted")
    assert probe.transcript_ch_sh(c2s, s2c) == T.transcript_ch_sh(c2s, s2c) == (ch, sh)
    for name in ("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"):
        assert probe.suite_hash(name) is T.suite_hash(name)

def test_probe_server_and_library_client_agree_on_the_draft_binder_over_a_real_handshake():
    """The probe passes (conn.received, conn.sent) as (client_to_server, server_to_client). If that
    order were wrong the two ends would disagree only on hardware. So: a server built from the
    PROBE's code, a client built from the library, one real TLS 1.3 handshake on loopback."""
    import socket, threading, sys
    from OpenSSL import SSL, crypto
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"))
    from relay_demo import make_identity
    k, key_pem, cert_pem = make_identity()
    tik_pub = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem))
    ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    out = {}
    def server():
        s, _ = srv.accept(); s.setblocking(True)
        conn = probe.BioConnection(ctx, s, server=True); conn.handshake()      # the probe's class
        ch, sh = probe.transcript_ch_sh(conn.received, conn.sent)               # the probe's argument order
        out["binder"] = probe.draft_binder(ch, sh, tik_pub, probe.suite_hash(conn.get_cipher_name()))
        conn.shutdown()
    th = threading.Thread(target=server); th.start()
    cctx = SSL.Context(SSL.TLS_METHOD); cctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    cs = socket.create_connection(("127.0.0.1", port))
    cl = T.BioConnection(cctx, cs, server=False); cl.handshake()               # the library's class
    ch, sh = T.transcript_ch_sh(cl.sent, cl.received)
    spki = x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, cl.get_peer_certificate())
           ).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    mine = T.draft_binder(ch, sh, spki, T.suite_hash(cl.get_cipher_name()))
    th.join(5); cl.shutdown()
    assert spki == tik_pub
    assert mine == out["binder"]
