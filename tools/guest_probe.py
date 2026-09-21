#!/usr/bin/env python3
"""HATLS guest probe -- runs INSIDE a real SEV-SNP guest.

A TLS 1.3 server. For each connection it derives, from ITS OWN side of the session, both the
RFC 9266 exporter and a session context, then walks a continuity chain: for counter = 0,1,2,...

    post_link = HKDF(exporter, prev_link || counter)      (prev_link = intra_link at counter 0)

and requests a real VCEK-signed SEV-SNP report with

    REPORT_DATA = SHA-512("HATLS-continuity-v0" || post_link)

so the hardware itself binds each link.

If the verifier sends a `head`, the report binds it too, so the chip witnesses the ledger state
the verifier claimed at that moment.

IMPORTANT (changed after the 21 Sep 2026 audit): this probe no longer accepts a transcript from
the client, and no longer sends its exporter or its public key on the wire. Both endpoints derive
the binding values independently from their own side of the TLS session, and the verifier takes
the identity key from the certificate the handshake proved possession of. A value that travels on
the wire cannot distinguish a direct session from a relayed one -- that was the v0.1 defect.

The TLS identity key (TIK) is injected by metadata, so a second guest launched with the same TIK
models re-hosting.
"""
import socket, json, hashlib, hmac, base64, struct, os, fcntl, ctypes, time

EXPORTER_LABEL = b"EXPERIMENTAL-hatls-continuity-exporter"    # ours, not RFC 9266's label
CONTEXT_LABEL  = b"EXPERIMENTAL-hatls-session-context"

def hkdf_expand_label(secret, label, ctx, n=32):
    full=b"EXPERIMENTAL-hatls "+label       # not the TLS 1.3 label space; see hatls/protocol.py; info=n.to_bytes(2,"big")+bytes([len(full)])+full+bytes([len(ctx)])+ctx
    out=t=b""; i=1
    while len(out)<n: t=hmac.new(secret,t+info+bytes([i]),hashlib.sha384).digest(); out+=t; i+=1
    return out[:n]
def intra_link(th, tik_pub):
    base=hkdf_expand_label(bytes(48),b"attestation base",th,48)
    return hkdf_expand_label(base,b"attestation",hashlib.sha384(tik_pub).digest(),32)
def post_link(exp,prev,counter):
    return hkdf_expand_label(exp,b"continuity",prev+counter.to_bytes(8,"big"),32)
def report_data_for(link, head=None):
    """With a head, the chip also commits to the ledger state the verifier claimed. The verifier
    cannot forge that witness afterwards, because the signature is the chip's, not its own."""
    if head is None: return hashlib.sha512(b"HATLS-continuity-v0"+link).digest()
    return hashlib.sha512(b"HATLS-continuity-v1"+link+head).digest()

class Req(ctypes.Structure):  _fields_=[("user_data",ctypes.c_ubyte*64),("vmpl",ctypes.c_uint32),("flags",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24)]
class Resp(ctypes.Structure): _fields_=[("status",ctypes.c_uint32),("report_size",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24),("report",ctypes.c_ubyte*4000)]
class Io(ctypes.Structure):   _fields_=[("msg_version",ctypes.c_ubyte),("req_data",ctypes.c_uint64),("resp_data",ctypes.c_uint64),("exitinfo2",ctypes.c_uint64)]
def snp_report(user_data):
    req=Req(); ctypes.memmove(req.user_data,user_data,64); req.vmpl=0; req.flags=0; resp=Resp()
    io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR); fcntl.ioctl(fd,0xC0205300,io); os.close(fd)
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError(f"fw_status {resp.status}")
    return bytes(resp.report[:1184])

def main():
    from OpenSSL import SSL, crypto
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization, hashes
    STAMP=time.strftime("%Y%m%dT%H%M%SZ",time.gmtime()); OUT=f"/root/hatls/{STAMP}"; os.makedirs(OUT,exist_ok=True); os.chdir(OUT)
    meta=lambda k: os.popen(f'curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/{k}').read()
    iid=meta("name"); zone=meta("zone").split("/")[-1]
    key_pem=open("/root/guest-tls.key","rb").read(); cert_pem=open("/root/guest-tls.crt","rb").read()
    priv=serialization.load_pem_private_key(key_pem,None)
    tik_pub=priv.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    ctx=SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_privatekey(priv); ctx.use_certificate(x509.load_pem_x509_certificate(cert_pem))
    srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); srv.bind(("0.0.0.0",8443)); srv.listen(5); srv.settimeout(10)
    deadline=time.time()+15*60; n=0
    json.dump({"instance":iid,"zone":zone,"tik_pub_sha256":hashlib.sha256(tik_pub).hexdigest(),"captured":STAMP},open("metadata.json","w"))
    print(f"HATLS guest {iid} @ {zone} serving 8443",flush=True)
    while time.time()<deadline:
        try: s,addr=srv.accept()
        except socket.timeout: continue
        n+=1; s.setblocking(True); conn=SSL.Connection(ctx,s); conn.set_accept_state()
        try:
            conn.do_handshake()
            line=b""
            while not line.endswith(b"\n") and len(line)<300: line+=conn.recv(1)
            req=json.loads(line.strip())
            if req.get("enroll"):
                # a real PKCS#10 CSR carrying THIS key, self-signed: the proof of possession.
                nonce=bytes.fromhex(req["nonce"])
                csr=(x509.CertificateSigningRequestBuilder()
                     .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"hatls-identity")]))
                     .sign(priv,hashes.SHA256())).public_bytes(serialization.Encoding.DER)
                rep=snp_report(hashlib.sha512(nonce+csr).digest())
                out=json.dumps({"instance":iid,"zone":zone,"enroll":True,"csr":csr.hex(),
                                "report":base64.b64encode(rep).decode()}).encode()
                conn.sendall(struct.pack(">I",len(out))+out)
                open(f"conn{n:02d}-enroll.bin","wb").write(rep)
                try: conn.shutdown()
                except Exception: pass
                s.close(); continue
            steps=int(req.get("steps",3))
            head=bytes.fromhex(req["head"]) if req.get("head") else None
            exp=conn.export_keying_material(EXPORTER_LABEL,32,b"")
            sc =conn.export_keying_material(CONTEXT_LABEL,48,b"")      # derived, never received
            chain=[]; prev=intra_link(sc,tik_pub)
            for counter in range(steps):
                pl=post_link(exp,prev if counter else intra_link(sc,tik_pub),counter)
                rep=snp_report(report_data_for(pl,head))
                open(f"conn{n:02d}-c{counter}-report.bin","wb").write(rep)
                chain.append({"counter":counter,"post_link":pl.hex(),"report":base64.b64encode(rep).decode()})
                prev=pl
            # NOTE: the exporter and the identity key are deliberately NOT sent. The verifier
            # derives the first from its own session and reads the second from the certificate.
            blob=json.dumps({"instance":iid,"zone":zone,"chain":chain,
                             "head":head.hex() if head else None}).encode()
            conn.sendall(struct.pack(">I",len(blob))+blob)
            json.dump(json.loads(blob),open(f"conn{n:02d}.json","w"))
            print(f"conn {n}: chain of {steps} links emitted, exporter {exp.hex()[:16]}",flush=True)
        except Exception as e:
            print(f"conn {n} error: {e!r}",flush=True)
        finally:
            try: conn.shutdown()
            except Exception: pass
            s.close()
if __name__=="__main__": main()
