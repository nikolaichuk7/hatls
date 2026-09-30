#!/usr/bin/env python3
"""After a HelloRetryRequest, which reading of "ClientHello...ServerHello" is the TLS stack's own?

examples/hrr_binder.py shows that four readings of that transcript give four binders. This script
asks the stack which of the four it uses itself.

A TLS 1.3 stack does not hand its transcript hash to the application: OpenSSL's public API gives
the handshake messages (message callback), the Finished values and the key log, but no call that
returns the running hash. The stack does commit to the transcript on the wire, though. Each
Finished message is an HMAC, under a key derived from a handshake traffic secret, over the
Transcript-Hash of everything before it (RFC 9846 Section 4.5.3; RFC 8446 Section 4.4.4). So the
check needs nothing from inside the stack:

  1. run a real TLS 1.3 handshake through a HelloRetryRequest, both ends in this process, and
     capture every wire byte, as examples/hrr_binder.py does;
  2. take the two handshake traffic secrets from the stack's own key log and decrypt both flights;
  3. rebuild the transcript from the captured messages, taking the part up to ServerHello under
     each of the four readings;
  4. recompute the server's and the client's Finished under each reading and compare them with
     the Finished messages the stack sent.

The reading under which both verify is the transcript the stack holds. It is reading (c): the
first ClientHello replaced by the synthetic message_hash message (RFC 9846 Section 4.1; RFC 8446
Section 4.4.1). The same result read the other way is what an implementer needs: a transcript
rebuilt from the observed handshake messages is the stack's transcript once that substitution is
applied, and is not the stack's transcript under any of the other three readings.

Usage:  PYTHONPATH=. python3 examples/hrr_finished_check.py [runs]
"""
import os, sys, ssl, hmac, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hatls.transcript import tls13_hkdf_expand_label, suite_hash, HRR_RANDOM
from hrr_binder import temp_identity
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

AEAD = {"TLS_AES_128_GCM_SHA256": (AESGCM, 16), "TLS_AES_256_GCM_SHA384": (AESGCM, 32),
        "TLS_CHACHA20_POLY1305_SHA256": (ChaCha20Poly1305, 32)}
C = "(c) message_hash:        msg_hash(CH1) || HRR || CH2 || SH"

def handshake(d, server_curve="secp384r1"):
    """One TLS 1.3 handshake as in hrr_binder.handshake, plus the stack's key log for it."""
    keylog = os.path.join(tempfile.mkdtemp(), "keylog.txt")
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(f"{d}/srv.crt", f"{d}/srv.key"); sctx.set_ecdh_curve(server_curve)
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cctx.check_hostname = False; cctx.verify_mode = ssl.CERT_NONE; cctx.keylog_filename = keylog
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
    secrets = {}
    with open(keylog) as f:
        for line in f:
            p = line.split()
            if len(p) == 3: secrets[p[0]] = bytes.fromhex(p[2])
    return c2s, s2c, c.cipher()[0], secrets

def _messages(buf):
    out = []
    while len(buf) >= 4:
        L = int.from_bytes(buf[1:4], "big")
        if len(buf) < 4 + L: break
        out.append(buf[:4+L]); buf = buf[4+L:]
    return out, buf

def flight(stream, secret, suite, H):
    """One direction of the handshake: (the plaintext handshake messages, the handshake messages
    decrypted under `secret`), each in wire order. Decryption stops at Finished; what follows on
    the wire is under the application traffic keys."""
    cipher, klen = AEAD[suite]
    aead = cipher(tls13_hkdf_expand_label(secret, b"key", b"", klen, H))
    iv = int.from_bytes(tls13_hkdf_expand_label(secret, b"iv", b"", 12, H), "big")
    plain = enc = b""; seq = 0; i = 0
    while i + 5 <= len(stream):
        ctype, header = stream[i], stream[i:i+5]
        body = stream[i+5:i+5+int.from_bytes(header[3:5], "big")]; i += 5 + len(body)
        if ctype == 0x16: plain += body
        elif ctype == 0x17:                             # TLSCiphertext: nonce = iv XOR sequence number
            inner = aead.decrypt((iv ^ seq).to_bytes(12, "big"), body, header).rstrip(b"\x00"); seq += 1
            if inner[-1] != 0x16: raise ValueError(f"expected a handshake record, got type {inner[-1]:#x}")
            enc += inner[:-1]
            done, rest = _messages(enc)
            if done and done[-1][0] == 0x14 and not rest: break
    return _messages(plain)[0], _messages(enc)[0]

def finished(secret, transcript, H):
    """verify_data of a Finished message: HMAC(finished_key, Transcript-Hash(transcript))."""
    key = tls13_hkdf_expand_label(secret, b"finished", b"", H().digest_size, H)
    return hmac.new(key, H(transcript).digest(), H).digest()

def check(c2s, s2c, suite, secrets):
    """{reading: (server Finished verifies, client Finished verifies)} for one captured handshake;
    a handshake without a HelloRetryRequest has the single reading 'CH || SH'."""
    H = suite_hash(suite)
    splain, senc = flight(s2c, secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"], suite, H)
    cplain, cenc = flight(c2s, secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], suite, H)
    assert senc[-1][0] == 0x14 and cenc[-1][0] == 0x14, "both flights must end in Finished"
    chs = [m for m in cplain if m[0] == 0x01]
    hrr = [m for m in splain if m[0] == 0x02 and m[6:38] == HRR_RANDOM]
    sh = [m for m in splain if m[0] == 0x02 and m[6:38] != HRR_RANDOM]
    assert len(sh) == 1 and len(chs) == 1 + len(hrr), "expected CH, SH or CH1, HRR, CH2, SH"
    if hrr:
        ch1, ch2, hrr, sh = chs[0], chs[1], hrr[0], sh[0]
        msg_hash = b"\xfe\x00\x00" + bytes([H().digest_size]) + H(ch1).digest()
        prefixes = {"(a) retry ignored:       CH1 || SH": ch1 + sh,
                    "(b) messages as sent:    CH1 || HRR || CH2 || SH": ch1 + hrr + ch2 + sh,
                    C: msg_hash + hrr + ch2 + sh,
                    "(d) 'the' CH is CH2:     CH2 || SH": ch2 + sh}
    else:
        prefixes = {"CH || SH": chs[0] + sh[0]}
    server_flight = b"".join(senc[:-1])                  # EncryptedExtensions ... CertificateVerify
    to_client_finished = b"".join(senc) + b"".join(cenc[:-1])     # ... server Finished
    s_key, c_key = secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"], secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]
    return {name: (hmac.compare_digest(finished(s_key, p + server_flight, H), senc[-1][4:]),
                   hmac.compare_digest(finished(c_key, p + to_client_finished, H), cenc[-1][4:]))
            for name, p in prefixes.items()}

def only_c(result):
    """True when both Finished verify under reading (c) and neither verifies under any other."""
    return all(v == ((True, True) if k == C else (False, False)) for k, v in result.items())

def main(runs=200):
    d, _ = temp_identity()
    c2s, s2c, suite, secrets = handshake(d)
    print(f"{ssl.OPENSSL_VERSION}; suite {suite}\n")
    print("does the Finished the stack sent verify over a transcript rebuilt under each reading? (one run)")
    print(f"  {'':60s} server Finished   client Finished")
    for k, (s_ok, c_ok) in check(c2s, s2c, suite, secrets).items():
        print(f"  {k:60s} {'verifies' if s_ok else 'fails':17s} {'verifies' if c_ok else 'fails'}")
    ok = sum(only_c(check(*handshake(d))) for _ in range(runs))
    print(f"\n  over {runs} HelloRetryRequest handshakes: both Finished verify under (c) and under no other reading in {ok} of {runs} runs")
    ctrl = check(*handshake(d, server_curve="X25519"))
    print(f"\n  control, both ends X25519, no retry: readings {list(ctrl)}; both Finished verify: {ctrl.get('CH || SH') == (True, True)}   (must be True)")
    return 0 if ok == runs and ctrl.get("CH || SH") == (True, True) else 1

if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 200))
