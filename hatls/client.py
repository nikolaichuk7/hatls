#!/usr/bin/env python3
"""The Relying Party's side of HATLS, done correctly.

Two values decide whether a relay is caught, and BOTH must be computed locally:

  * the RFC 9266 exporter of the verifier's OWN TLS session, and
  * the identity key, read out of the certificate the peer proved possession of in the handshake.

Copying either from the peer's message proves nothing, because a relay forwards both unchanged.
v0.1 of this repository read both off the wire, so a relay was accepted; see docs/AUDIT.md.

On certificate validation: HATLS does not need a CA to decide who the peer is. TLS 1.3
CertificateVerify already proves the peer holds the private half of the certificate it presented,
and the mandate says whether THAT key is enrolled and still on its own instance. The trust anchor
is the mandate, not a web PKI. Pass `ca_file` if a deployment also wants PKI validation.
"""
import json, socket, struct
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# NOT RFC 9266's "EXPORTER-Channel-Binding". That label means tls-exporter channel binding, and
# borrowing it for a different purpose invites exactly the collision exporters exist to prevent.
# These are ours, unregistered, and named so that nobody mistakes them for something standard.
EXPORTER_LABEL = b"EXPERIMENTAL-hatls-continuity-exporter"
CONTEXT_LABEL  = b"EXPERIMENTAL-hatls-session-context"

class HatlsClient:
    """A TLS 1.3 client that derives every security-relevant value from its own connection."""

    def __init__(self, host, port, timeout=30, ca_file=None):
        self.host, self.port, self.timeout, self.ca_file = host, port, timeout, ca_file
        self.conn = None; self._sock = None

    def __enter__(self):
        ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        if self.ca_file:
            ctx.load_verify_locations(self.ca_file)
            ctx.set_verify(SSL.VERIFY_PEER, lambda c, x, e, d, ok: bool(ok))
        else:
            ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(None)          # pyOpenSSL needs a blocking socket
        self.conn = SSL.Connection(ctx, self._sock)
        self.conn.set_connect_state(); self.conn.do_handshake()
        return self

    def __exit__(self, *exc):
        for closer in (lambda: self.conn.shutdown(), lambda: self._sock.close()):
            try: closer()
            except Exception: pass
        return False

    # ---- values derived locally; never accepted from the peer ----
    @property
    def exporter(self):
        """An RFC 8446 exporter of THIS connection, under our own label. In a relay it differs
        from the guest's, which is the whole point."""
        return self.conn.export_keying_material(EXPORTER_LABEL, 32, b"")

    @property
    def session_context(self):
        """The intra binder's input. Both endpoints derive it independently from the same TLS
        session, so neither has to send it. NOTE: this is a session-bound stand-in for a true
        handshake-transcript checkpoint, which needs a hook into the TLS stack -- open item."""
        return self.conn.export_keying_material(CONTEXT_LABEL, 48, b"")

    @property
    def peer_identity_key(self):
        """The TIK: the SPKI of the certificate the peer proved possession of during the
        handshake. This, not a field in the JSON, is the identity the mandate appraises."""
        der = crypto.dump_certificate(crypto.FILETYPE_ASN1, self.conn.get_peer_certificate())
        return x509.load_der_x509_certificate(der).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    # ---- framing ----
    def _recv(self, n):
        b = b""
        while len(b) < n:
            chunk = self.conn.recv(n - len(b))
            if not chunk: raise ConnectionError("peer closed mid-message")
            b += chunk
        return b

    def request(self, obj):
        """Send one JSON request, read one length-prefixed JSON reply."""
        self.conn.sendall((json.dumps(obj) + "\n").encode())
        n = struct.unpack(">I", self._recv(4))[0]
        return json.loads(self._recv(n))
