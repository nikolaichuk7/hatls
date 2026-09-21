#!/usr/bin/env python3
"""Relay defence, reproducible on a laptop -- no cloud, no confidential VM.

Three real TLS 1.3 endpoints on localhost:

    client  ->  GUEST            (direct)
    client  ->  RELAY  ->  GUEST (the relay holds the guest's STOLEN TLS key)

The relay is the strongest key-theft attacker in the threat model: it terminates the client's TLS
with the genuine key and forwards the guest's genuine, hardware-signed evidence untouched. Nothing
it sends is forged. It is caught for one reason only -- the verifier derives the exporter
from ITS OWN side of the connection, and the relay cannot make two different TLS sessions agree.

v0.1 of this repository read that exporter out of the peer's JSON, so this attack succeeded. Run
this file to watch it fail now.  Usage:  PYTHONPATH=. python3 examples/relay_demo.py
"""
import os, sys, json, socket, struct, hashlib, threading, datetime
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hatls.protocol import Attester, Mandate, make_enrolment_csr, csr_public_key_der
from hatls.tee import MockTEE, mock_verifier
from hatls.client import HatlsClient, EXPORTER_LABEL, CONTEXT_LABEL

CHIP=(b"\xa2\xb2\x58\x0a"*16)[:64]
GUEST_PORT, RELAY_PORT = 18443, 18444

def make_identity():
    k=ec.generate_private_key(ec.SECP256R1())
    n=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"hatls-guest")])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(n).issuer_name(n)
          .public_key(k.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(days=1))
          .not_valid_after(now+datetime.timedelta(days=1)).sign(k,hashes.SHA256()))
    return (k,
            k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM))

def _recv(c,n):
    b=b""
    while len(b)<n:
        d=c.recv(n-len(b))
        if not d: raise ConnectionError("closed")
        b+=d
    return b
def _line(c):
    b=b""
    while not b.endswith(b"\n"): b+=c.recv(1)
    return b

def _server_ctx(key_pem, cert_pem):
    # pyOpenSSL takes cryptography objects directly; its own PKey/X509 wrappers are deprecated
    # and warn, which is not what a first run of someone else's code should print.
    ctx=SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_privatekey(serialization.load_pem_private_key(key_pem, None))
    ctx.use_certificate(x509.load_pem_x509_certificate(cert_pem))
    return ctx

def guest_server(priv, key_pem, cert_pem, tee, conns, ready):
    """The attester. It derives the session context from its OWN side too -- nothing is taken
    from the client, and nothing security-relevant is sent in the clear."""
    ctx=_server_ctx(key_pem,cert_pem)
    tik=x509.load_pem_x509_certificate(cert_pem).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind(("127.0.0.1",GUEST_PORT)); srv.listen(5); ready.set()
    for _ in range(conns):
        s,_a=srv.accept(); s.setblocking(True)
        c=SSL.Connection(ctx,s); c.set_accept_state()
        try:
            c.do_handshake(); req=json.loads(_line(c))
            if req.get("enroll"):
                nonce=bytes.fromhex(req["nonce"]); csr=make_enrolment_csr(priv)
                out={"csr":csr.hex(), "evidence":tee.report(hashlib.sha512(nonce+csr).digest())}
            else:
                exp=c.export_keying_material(EXPORTER_LABEL,32,b"")
                sc =c.export_keying_material(CONTEXT_LABEL,48,b"")
                att=Attester(tee,tik)
                out={"chain":[att.attest(sc,exp) for _ in range(int(req.get("steps",2)))]}
            blob=json.dumps(out).encode(); c.sendall(struct.pack(">I",len(blob))+blob)
        except Exception as e: print(f"   [guest] {e!r}")
        finally:
            try: c.shutdown()
            except Exception: pass
            s.close()
    srv.close()

def relay(key_pem, cert_pem, ready):
    """A thief who stole the guest's TLS key. Forwards everything verbatim."""
    ctx=_server_ctx(key_pem,cert_pem)
    srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind(("127.0.0.1",RELAY_PORT)); srv.listen(1); ready.set()
    s,_a=srv.accept(); s.setblocking(True)
    down=SSL.Connection(ctx,s); down.set_accept_state()
    try:
        down.do_handshake(); line=_line(down)
        up_ctx=SSL.Context(SSL.TLS_METHOD); up_ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        up_ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        us=socket.create_connection(("127.0.0.1",GUEST_PORT)); us.setblocking(True)
        up=SSL.Connection(up_ctx,us); up.set_connect_state(); up.do_handshake()
        up.sendall(line)
        n=struct.unpack(">I",_recv(up,4))[0]; blob=_recv(up,n)
        down.sendall(struct.pack(">I",n)+blob)          # genuine evidence, untouched
        e_up=up.export_keying_material(EXPORTER_LABEL,32,b"")
        e_dn=down.export_keying_material(EXPORTER_LABEL,32,b"")
        print(f"   [relay] forwarded genuine evidence; guest-side exporter {e_up.hex()[:12]}, "
              f"client-side {e_dn.hex()[:12]} -- the relay cannot make these agree")
        for x in (up,down):
            try: x.shutdown()
            except Exception: pass
        us.close()
    finally:
        s.close(); srv.close()

def feed(m, cl, blob, label):
    ok=None
    for step in blob["chain"]:
        ok,why=m.present(cl.peer_identity_key, cl.session_context, cl.exporter, step)
        print(f"   {label} counter {step['counter']}: accepted={ok}  {why}")
        if not ok: break
    return ok

def main():
    priv,key_pem,cert_pem=make_identity(); tee=MockTEE(CHIP)
    m=Mandate(mock_verifier({tee.pub.hex()}))
    up=threading.Event()
    threading.Thread(target=guest_server,args=(priv,key_pem,cert_pem,tee,3,up),daemon=True).start()
    assert up.wait(10), "guest did not come up" 

    print("=== ENROLMENT: bind the identity key to the instance it was born on ===")
    with HatlsClient("127.0.0.1",GUEST_PORT) as cl:
        nonce=m.challenge()
        r=cl.request({"enroll":True,"nonce":nonce.hex()})
        csr=bytes.fromhex(r["csr"])
        # the CSR must carry the key THIS client saw in the handshake -- checked locally
        assert csr_public_key_der(csr)==cl.peer_identity_key, "CSR does not match the TLS peer key"
        ok,why=m.enroll(cl.peer_identity_key, r["evidence"], nonce, csr)
        print(f"   enrolled={ok} ({why})")

    print("\n=== CONTROL: the client talks to the guest directly ===")
    with HatlsClient("127.0.0.1",GUEST_PORT) as cl:
        direct=feed(m, cl, cl.request({"steps":2}), "direct")

    print("\n=== ATTACK: the same client, through a relay holding the guest's stolen key ===")
    rup=threading.Event()
    threading.Thread(target=relay,args=(key_pem,cert_pem,rup),daemon=True).start()
    assert rup.wait(10), "relay did not come up" 
    with HatlsClient("127.0.0.1",RELAY_PORT) as cl:
        relayed=feed(m, cl, cl.request({"steps":2}), "relayed")

    print("\n--- mandate log ---")
    for e in m.log: print("   ",e)
    print(f"\n  direct accepted : {direct}")
    print(f"  relay  accepted : {relayed}")
    print("\n  RESULT:", "relay stopped, honest client unaffected" if (direct and not relayed)
          else "*** UNEXPECTED -- investigate ***")
    return 0 if (direct and not relayed) else 1

if __name__=="__main__": sys.exit(main())
