"""The binder of draft-fossati-seat-early-attestation-07, computed exactly as Section 5.1.1 says.

This module exists for ONE purpose: to run that draft's own binder -- not an analogue -- through the
Section 8.4 experiment on real hardware. It is not part of the HATLS protocol, whose links use the
"EXPERIMENTAL-hatls " label space and the session exporter (see hatls/protocol.py). Nothing here
changes what the mandate accepts.

Section 5.1.1, verbatim:

    attest_base     = HKDF-Expand-Label(0, "attestation base", Hash(ClientHello...ServerHello), Hash.length)
    s_attest_binder = HKDF-Expand-Label(attest_base, "attestation", Hash(TLS_Server_Public_Key), Hash.length)

    "TLS_Server_Public_Key denote[s] the DER-encoded SubjectPublicKeyInfo of the peer's end-entity
     certificate. Hash is the cipher suite hash function for the handshake. [...] The "0" parameter
     denotes a byte string of Hash.length zeroes."

HKDF-Expand-Label is RFC 8446 Section 7.1, with the "tls13 " prefix; Hash(ClientHello...ServerHello)
is the Transcript-Hash of RFC 8446 Section 4.4.1 over the two handshake messages, headers included.
`tls13_hkdf_expand_label` is checked byte for byte against the RFC 8448 trace in the tests.

To see ClientHello and ServerHello, the TLS connection runs over memory BIOs, so every byte that
crosses the wire passes through Python first. `BioConnection` does that for either endpoint.
"""
import hashlib, hmac
from OpenSSL import SSL

HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

def tls13_hkdf_expand_label(secret, label, context, length, H):
    """RFC 8446 Section 7.1. `H` is a hashlib constructor (sha256 / sha384)."""
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return _hkdf_expand(secret, info, length, H)

def _hkdf_expand(prk, info, length, H):
    out = t = b""; i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), H).digest(); out += t; i += 1
    return out[:length]

def suite_hash(cipher_name):
    """The cipher suite's hash, from the name OpenSSL reports for a TLS 1.3 connection."""
    if cipher_name.endswith("_SHA384"): return hashlib.sha384
    if cipher_name.endswith("_SHA256"): return hashlib.sha256
    raise ValueError(f"not a TLS 1.3 suite: {cipher_name}")

def first_handshake_message(stream, msg_type):
    """The first handshake message of `msg_type` in a raw TLS byte stream, WITH its 4-byte header,
    reassembled across records if it spans several. None if the first handshake message is of
    another type or is incomplete."""
    i = 0; hs = b""
    while i + 5 <= len(stream):
        ctype = stream[i]; rlen = int.from_bytes(stream[i+3:i+5], "big")
        body = stream[i+5:i+5+rlen]; i += 5 + rlen
        if ctype != 0x16:
            if hs: break
            continue
        hs += body
        if len(hs) >= 4:
            t = hs[0]; L = int.from_bytes(hs[1:4], "big")
            if len(hs) >= 4 + L:
                return hs[:4+L] if t == msg_type else None
    return None

def transcript_ch_sh(client_to_server, server_to_client):
    """ClientHello and ServerHello as sent on the wire. Refuses a HelloRetryRequest handshake,
    whose transcript is computed differently (RFC 8446 Section 4.4.1) and is not modelled here."""
    ch = first_handshake_message(client_to_server, 0x01)
    sh = first_handshake_message(server_to_client, 0x02)
    if ch is None or sh is None:
        raise ValueError("could not find ClientHello/ServerHello at the start of the streams")
    if sh[6:38] == HRR_RANDOM:
        raise ValueError("HelloRetryRequest handshake: the CH..SH transcript is not the simple concatenation")
    return ch, sh

def draft_binder(ch, sh, server_spki_der, H):
    """s_attest_binder of Section 5.1.1: Hash.length bytes."""
    L = H().digest_size
    transcript_hash = H(ch + sh).digest()
    base = tls13_hkdf_expand_label(bytes(L), b"attestation base", transcript_hash, L, H)
    return tls13_hkdf_expand_label(base, b"attestation", H(server_spki_der).digest(), L, H)

def binder_report_data(binder):
    """The binder placed in REPORT_DATA as the draft's 'nonce value': left-aligned, zero-padded
    to the 64 bytes SEV-SNP provides. The draft does not fix an encoding for SEV-SNP; this is the
    most literal reading, and any deterministic one gives the same Section 8.4 result."""
    assert len(binder) <= 64
    return binder + bytes(64 - len(binder))

class BioConnection:
    """A TLS connection over memory BIOs: OpenSSL never touches the socket, so the bytes of the
    handshake are ours to record. `sent`/`received` hold everything up to and including the
    handshake; the two Hello messages are at the front of each."""
    def __init__(self, context, sock, server):
        self.conn = SSL.Connection(context, None); self.sock = sock
        (self.conn.set_accept_state if server else self.conn.set_connect_state)()
        self.sent = b""; self.received = b""; self._recording = True

    def _flush(self):
        while True:
            try: data = self.conn.bio_read(65536)
            except SSL.WantReadError: return
            self.sock.sendall(data)
            if self._recording: self.sent += data

    def _feed(self):
        data = self.sock.recv(65536)
        if not data: raise ConnectionError("peer closed")
        if self._recording: self.received += data
        self.conn.bio_write(data)

    def handshake(self):
        while True:
            try:
                self.conn.do_handshake(); self._flush(); break
            except SSL.WantReadError:
                self._flush(); self._feed()
        self._recording = False

    def recv(self, n):
        while True:
            try:
                data = self.conn.recv(n); self._flush(); return data
            except SSL.WantReadError:
                self._flush(); self._feed()

    def recv_exact(self, n):
        b = b""
        while len(b) < n:
            d = self.recv(n - len(b))
            if not d: raise ConnectionError("closed")
            b += d
        return b

    def sendall(self, data):
        self.conn.sendall(data); self._flush()

    def shutdown(self):
        try: self.conn.shutdown(); self._flush()
        except Exception: pass

    def __getattr__(self, name):                 # export_keying_material, get_cipher_name, ...
        return getattr(self.conn, name)
