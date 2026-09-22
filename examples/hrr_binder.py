#!/usr/bin/env python3
"""With a HelloRetryRequest, "Hash(ClientHello...ServerHello)" has four readings, and they differ.

draft-fossati-seat-early-attestation-07, Section 5.1.1, derives the attestation binder from
Hash(ClientHello...ServerHello). The words HelloRetryRequest and message_hash do not occur in the
document. But RFC 8446 Section 4.4.1 says that when a HelloRetryRequest occurs the transcript is
NOT the messages as sent: ClientHello1 is replaced by a synthetic message_hash message. So a
conforming implementer of 5.1.1 has at least four defensible readings:

  (a) retry ignored               Hash(CH1 || SH)
  (b) messages as sent            Hash(CH1 || HRR || CH2 || SH)
  (c) RFC 8446 4.4.1              Hash(message_hash(CH1) || HRR || CH2 || SH)
  (d) "the" ClientHello = second  Hash(CH2 || SH)

Appendix C of the draft points implementers at "callback interfaces" that expose the messages
as sent -- which yields (a) or (b); a stack's own transcript hash at ServerHello yields (c). Two
conforming peers that pick differently do not just fail to connect: Section 5.1.2 makes a binder
mismatch a fatal attestation_failed alert, so a disagreement about text is reported as a
statement about the peer.

A HelloRetryRequest is not exotic: it is what happens whenever the client's offered key_share is
not the group the server will use -- the ordinary state of a post-quantum migration.

This script runs real TLS 1.3 handshakes in-process (stdlib ssl, memory BIOs, no network), forces
a HelloRetryRequest by offering a key share the server will not take, captures the plaintext
handshake messages, computes the 5.1.1 binder under each reading with the same RFC 8448-checked
HKDF as hatls/transcript.py, and checks the invariant over many runs: the four readings never
coincide.

Usage:  PYTHONPATH=. python3 examples/hrr_binder.py [runs]
"""
import os, sys, ssl, hashlib, tempfile, datetime
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.transcript import tls13_hkdf_expand_label, suite_hash, HRR_RANDOM
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def temp_identity():
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hrr-experiment")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(k, hashes.SHA256()))
    d = tempfile.mkdtemp()
    open(f"{d}/srv.key", "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    open(f"{d}/srv.crt", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    spki = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return d, spki

def handshake(d, server_curve="secp384r1", client_curve=None):
    """One TLS 1.3 handshake, both ends in this process, every wire byte captured per direction.
    Pass client_curve to pin the client's single group (used for the no-HRR control)."""
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(f"{d}/srv.crt", f"{d}/srv.key"); sctx.set_ecdh_curve(server_curve)
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cctx.check_hostname = False; cctx.verify_mode = ssl.CERT_NONE
    if client_curve: cctx.set_ecdh_curve(client_curve)
    # default client: offers an X25519 key_share but SUPPORTS P-384 too; a server restricted to
    # P-384 therefore answers with a HelloRetryRequest asking for a P-384 share -- the ordinary
    # shape of a group migration, not a failure.
    cin, cout, sin, sout = (ssl.MemoryBIO() for _ in range(4))
    c = cctx.wrap_bio(cin, cout, server_hostname="hrr.local"); s = sctx.wrap_bio(sin, sout, server_side=True)
    c2s = s2c = b""
    for _ in range(40):
        done = 0
        for obj, outbio, peer in ((c, cout, sin), (s, sout, cin)):
            try: obj.do_handshake(); done += 1
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError): pass
            data = outbio.read()
            if data:
                if obj is c: c2s += data
                else: s2c += data
                peer.write(data)
        if done == 2: break
    return c2s, s2c, c.cipher()[0]

def plaintext_handshake_messages(stream):
    """Handshake messages from the plaintext records at the front of a stream, in order."""
    out, i, hs = [], 0, b""
    while i + 5 <= len(stream):
        ct = stream[i]; ln = int.from_bytes(stream[i+3:i+5], "big"); body = stream[i+5:i+5+ln]; i += 5 + ln
        if ct == 0x16: hs += body
        elif ct == 0x14: continue                       # middlebox-compat ChangeCipherSpec
        else: break                                     # encrypted from here on
    while len(hs) >= 4:
        L = int.from_bytes(hs[1:4], "big")
        if len(hs) < 4 + L: break
        out.append(hs[:4+L]); hs = hs[4+L:]
    return out

def binder(transcript_hash, spki, H):
    L = H().digest_size
    base = tls13_hkdf_expand_label(bytes(L), b"attestation base", transcript_hash, L, H)
    return tls13_hkdf_expand_label(base, b"attestation", H(spki).digest(), L, H)

def four_readings(c2s, s2c, spki, H):
    cmsgs = [m for m in plaintext_handshake_messages(c2s) if m[0] == 0x01]
    smsgs = [m for m in plaintext_handshake_messages(s2c) if m[0] == 0x02]
    hrr = [m for m in smsgs if m[6:38] == HRR_RANDOM]; sh = [m for m in smsgs if m[6:38] != HRR_RANDOM]
    assert len(cmsgs) == 2 and len(hrr) == 1 and len(sh) == 1, "expected CH1, HRR, CH2, SH"
    ch1, ch2, hrr, sh = cmsgs[0], cmsgs[1], hrr[0], sh[0]
    msg_hash = b"\xfe\x00\x00" + bytes([H().digest_size]) + H(ch1).digest()      # RFC 8446 4.4.1
    readings = {
        "(a) retry ignored:       Hash(CH1 || SH)":                      H(ch1 + sh).digest(),
        "(b) messages as sent:    Hash(CH1 || HRR || CH2 || SH)":        H(ch1 + hrr + ch2 + sh).digest(),
        "(c) RFC 8446 4.4.1:      Hash(msg_hash(CH1) || HRR || CH2 || SH)": H(msg_hash + hrr + ch2 + sh).digest(),
        "(d) 'the' CH is CH2:     Hash(CH2 || SH)":                      H(ch2 + sh).digest(),
    }
    return {k: binder(v, spki, H) for k, v in readings.items()}, (len(ch1), len(hrr), len(ch2), len(sh))

def main(runs=200):
    d, spki = temp_identity()
    c2s, s2c, suite = handshake(d); H = suite_hash(suite)
    b, sizes = four_readings(c2s, s2c, spki, H)
    print(f"suite {suite}; ClientHello1 {sizes[0]} B, HelloRetryRequest {sizes[1]} B, ClientHello2 {sizes[2]} B, ServerHello {sizes[3]} B\n")
    print("the Section 5.1.1 binder under each reading of 'ClientHello...ServerHello' (one run):")
    for k, v in b.items(): print(f"  {k:66s} {v.hex()[:32]}...")
    print(f"\n  distinct binders from the four readings: {len(set(b.values()))} of 4")
    all4 = 0
    for _ in range(runs):
        c2s, s2c, suite = handshake(d); b, _ = four_readings(c2s, s2c, spki, suite_hash(suite))
        all4 += (len(set(b.values())) == 4)
    print(f"\n  over {runs} HelloRetryRequest handshakes: four distinct binders in {all4} of {runs} runs")
    print("  (the values differ every run -- fresh randoms -- the invariant is that the readings never coincide)")
    ctrl_c2s, ctrl_s2c, suite = handshake(d, server_curve="X25519")
    hrr_ctrl = any(m[6:38] == HRR_RANDOM for m in plaintext_handshake_messages(ctrl_s2c))
    print(f"\n  control, both ends X25519: HelloRetryRequest occurred: {hrr_ctrl}   (must be False)")
    return 0

if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 200))
