"""hatls/transcript.py: the draft's binder must be THEIR binder, byte for byte.

The Section 8.4 experiment is only worth running with the exact construction of
draft-fossati-seat-early-attestation-07 Section 5.1.1. Two things could silently make it an
analogue again: a wrong HKDF-Expand-Label encoding, or a wrong transcript. So:

  * HKDF-Expand-Label is checked against the RFC 8448 TLS 1.3 trace, which prints the `info`
    bytes and the output for "tls13 derived";
  * the transcript is checked on a real TLS 1.3 handshake over loopback, where the client and
    the server each record their own view of the wire and must compute the same binder.
"""
import hashlib, hmac, socket, threading, sys, os
import pytest
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"))
from relay_demo import make_identity
from hatls import transcript as T

# ---- RFC 8448 Section 3, "derive secret for handshake 'tls13 derived'" ----
RFC8448_EARLY_SECRET = bytes.fromhex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
RFC8448_DERIVED      = bytes.fromhex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
RFC8448_INFO         = bytes.fromhex("00200d746c73313320646572697665642"
                                     "0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

def test_early_secret_is_the_documented_one():
    # HKDF-Extract(salt=0, IKM=0^32) with SHA-256 -- the value RFC 8448 prints.
    assert hmac.new(bytes(32), bytes(32), hashlib.sha256).digest() == RFC8448_EARLY_SECRET

def test_hkdf_expand_label_matches_rfc8448_byte_for_byte():
    got = T.tls13_hkdf_expand_label(RFC8448_EARLY_SECRET, b"derived", hashlib.sha256(b"").digest(), 32, hashlib.sha256)
    assert got == RFC8448_DERIVED

def test_hkdf_info_encoding_matches_rfc8448():
    # the 49 `info` octets RFC 8448 prints: len(2) | len(label) | "tls13 derived" | len(ctx) | ctx
    full = b"tls13 " + b"derived"; ctx = hashlib.sha256(b"").digest()
    info = (32).to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    assert info == RFC8448_INFO and len(info) == 49
    assert T._hkdf_expand(RFC8448_EARLY_SECRET, info, 32, hashlib.sha256) == RFC8448_DERIVED

# ---- record / handshake parsing ----
def _rec(ctype, body): return bytes([ctype, 3, 3]) + len(body).to_bytes(2, "big") + body
def _hs(t, body):      return bytes([t]) + len(body).to_bytes(3, "big") + body

def test_first_handshake_message_in_one_record():
    ch = _hs(0x01, b"client hello body")
    assert T.first_handshake_message(_rec(0x16, ch) + _rec(0x14, b"\x01"), 0x01) == ch

def test_first_handshake_message_split_across_records():
    ch = _hs(0x01, bytes(range(200)))
    stream = _rec(0x16, ch[:50]) + _rec(0x16, ch[50:])
    assert T.first_handshake_message(stream, 0x01) == ch

def test_wrong_first_message_type_is_none():
    assert T.first_handshake_message(_rec(0x16, _hs(0x02, b"sh")), 0x01) is None

def test_hello_retry_request_is_refused():
    ch = _hs(0x01, b"x" * 40)
    sh = _hs(0x02, b"\x03\x03" + T.HRR_RANDOM + b"\x00" * 10)
    with pytest.raises(ValueError, match="HelloRetryRequest"):
        T.transcript_ch_sh(_rec(0x16, ch), _rec(0x16, sh))

# ---- a real TLS 1.3 handshake over loopback, both ends recording ----
def _ctx_server(key_pem, cert_pem):
    ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem))
    ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
    return ctx

def _ctx_client():
    ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    return ctx

def _handshake_pair(key_pem, cert_pem):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    out = {}
    def server():
        s, _ = srv.accept(); s.setblocking(True)
        c = T.BioConnection(_ctx_server(key_pem, cert_pem), s, server=True); c.handshake()
        out["server"] = c
    th = threading.Thread(target=server); th.start()
    cs = socket.create_connection(("127.0.0.1", port))
    cl = T.BioConnection(_ctx_client(), cs, server=False); cl.handshake()
    th.join(5); return cl, out["server"]

def test_both_ends_compute_the_same_draft_binder():
    k, key_pem, cert_pem = make_identity()
    cl, sv = _handshake_pair(key_pem, cert_pem)
    # each end uses ITS OWN recording of the wire
    ch_c, sh_c = T.transcript_ch_sh(cl.sent, cl.received)
    ch_s, sh_s = T.transcript_ch_sh(sv.received, sv.sent)
    assert ch_c == ch_s and sh_c == sh_s
    assert ch_c[0] == 0x01 and sh_c[0] == 0x02
    H = T.suite_hash(cl.get_cipher_name()); assert H is T.suite_hash(sv.get_cipher_name())
    spki_server = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    spki_client_view = x509.load_der_x509_certificate(
        crypto.dump_certificate(crypto.FILETYPE_ASN1, cl.get_peer_certificate())
    ).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert spki_server == spki_client_view
    b_client = T.draft_binder(ch_c, sh_c, spki_client_view, H)
    b_server = T.draft_binder(ch_s, sh_s, spki_server, H)
    assert b_client == b_server and len(b_client) == H().digest_size
    cl.shutdown(); sv.shutdown()

def test_two_connections_have_different_binders():
    k, key_pem, cert_pem = make_identity()
    spki = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    binders = []
    for _ in range(2):
        cl, sv = _handshake_pair(key_pem, cert_pem)
        ch, sh = T.transcript_ch_sh(cl.sent, cl.received)
        binders.append(T.draft_binder(ch, sh, spki, T.suite_hash(cl.get_cipher_name())))
        cl.shutdown(); sv.shutdown()
    assert binders[0] != binders[1]         # fresh randoms and key shares: a new transcript

def test_application_data_still_flows_over_bio_connection():
    k, key_pem, cert_pem = make_identity()
    cl, sv = _handshake_pair(key_pem, cert_pem)
    cl.sendall(b"ping\n"); assert sv.recv_exact(5) == b"ping\n"
    sv.sendall(b"pong\n"); assert cl.recv_exact(5) == b"pong\n"
    assert cl.export_keying_material(b"x", 32, b"") == sv.export_keying_material(b"x", 32, b"")
    cl.shutdown(); sv.shutdown()

def test_binder_report_data_is_64_bytes_left_aligned():
    b = bytes(range(48))
    rd = T.binder_report_data(b)
    assert len(rd) == 64 and rd[:48] == b and rd[48:] == bytes(16)
