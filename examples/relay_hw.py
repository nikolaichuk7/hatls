#!/usr/bin/env python3
"""Relay defence against a REAL SEV-SNP guest, with a REAL stolen key.

The relay holds the guest's genuine TLS identity key -- the strongest key-theft attacker in the
threat model. It terminates our TLS with that key, opens its own TLS session to the confidential
VM, and forwards the guest's genuine, VCEK-signed attestation reports untouched. Nothing is forged
at any point; AMD's own signature covers every byte of evidence it passes along.

It is caught for exactly one reason: the verifier derives the RFC 9266 exporter from its own side
of the connection, and no relay can make two distinct TLS sessions agree on it.

Usage:  PYTHONPATH=. python3 examples/relay_hw.py <guest-ip>
"""
import os, sys, json, socket, struct, hashlib, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from OpenSSL import SSL, crypto
from hatls.protocol import Mandate, report_data_for, csr_public_key_der
from hatls.tee import sevsnp_verifier
from hatls.client import HatlsClient, EXPORTER_LABEL

RELAY_PORT = 18543

def _recv(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: raise ConnectionError("closed")
        b += d
    return b

def relay(guest_ip, key_pem, cert_pem, ready, note):
    """A thief holding the guest's stolen TLS key. Forwards everything verbatim."""
    ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem))
    ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", RELAY_PORT)); srv.listen(1); ready.set()
    s, _a = srv.accept(); s.setblocking(True)
    down = SSL.Connection(ctx, s); down.set_accept_state()
    try:
        down.do_handshake()
        line = b""
        while not line.endswith(b"\n"): line += down.recv(1)
        up_ctx = SSL.Context(SSL.TLS_METHOD); up_ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        up_ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        us = socket.create_connection((guest_ip, 8443), timeout=30); us.setblocking(True)
        up = SSL.Connection(up_ctx, us); up.set_connect_state(); up.do_handshake()
        up.sendall(line)
        n = struct.unpack(">I", _recv(up, 4))[0]; blob = _recv(up, n)
        down.sendall(struct.pack(">I", n) + blob)
        note["guest_side"] = up.export_keying_material(EXPORTER_LABEL, 32, b"").hex()
        note["client_side"] = down.export_keying_material(EXPORTER_LABEL, 32, b"").hex()
        for x in (up, down):
            try: x.shutdown()
            except Exception: pass
        us.close()
    except Exception as e:
        note["error"] = repr(e)
    finally:
        s.close(); srv.close()

def as_evidence(step):
    return {"counter": step["counter"], "post_link": step["post_link"],
            "evidence": {"kind": "sev-snp", "report": step["report"],
                         "report_data": report_data_for(bytes.fromhex(step["post_link"])).hex()}}

def main():
    guest_ip = sys.argv[1]
    OUT = f"evidence/relay-hw-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"; os.makedirs(OUT, exist_ok=True)
    key_pem = open("tik.key", "rb").read(); cert_pem = open("tik.crt", "rb").read()
    m = Mandate(sevsnp_verifier())
    out = {"guest": guest_ip}

    print(f"=== ENROLMENT against the real guest {guest_ip} ===")
    with HatlsClient(guest_ip, 8443) as cl:
        nonce = m.challenge()
        r = cl.request({"enroll": True, "nonce": nonce.hex()})
        csr = bytes.fromhex(r["csr"]); tik = cl.peer_identity_key
        assert csr_public_key_der(csr) == tik, "CSR does not carry the TLS peer key"
        ev = {"kind": "sev-snp", "report": r["report"],
              "report_data": hashlib.sha512(nonce + csr).digest().hex()}
        ok, why = m.enroll(tik, ev, nonce, csr)
        import base64
        from hatls.tee import parse_snp, snp_anchor
        f = parse_snp(base64.b64decode(r["report"])); a = snp_anchor(f)
        inst = a["instance"].hex()[:16]; place = a["place"].hex()[:16] if a["place"] else "masked"
        print(f"   zone {r['zone']}, instance {inst}, place {place}: enrolled={ok} ({why})")
        out["enrolled"] = ok; out["instance"] = inst; out["place"] = place; out["zone"] = r["zone"]
        json.dump(r, open(f"{OUT}/enroll.json", "w"))
        if not ok: return 1

    print("\n=== CONTROL: straight to the confidential VM ===")
    with HatlsClient(guest_ip, 8443) as cl:
        blob = cl.request({"steps": 2}); json.dump(blob, open(f"{OUT}/direct.json", "w"))
        direct = None
        for step in blob["chain"]:
            direct, why = m.present(cl.peer_identity_key, cl.session_context, cl.exporter, as_evidence(step))
            print(f"   direct counter {step['counter']}: accepted={direct}  {why}")
            if not direct: break
    out["direct_accepted"] = direct

    print("\n=== ATTACK: through a relay holding the guest's real stolen key ===")
    ready = threading.Event(); note = {}
    threading.Thread(target=relay, args=(guest_ip, key_pem, cert_pem, ready, note), daemon=True).start()
    assert ready.wait(15), "relay did not come up"
    with HatlsClient("127.0.0.1", RELAY_PORT) as cl:
        blob = cl.request({"steps": 2}); json.dump(blob, open(f"{OUT}/relayed.json", "w"))
        print(f"   relay forwarded genuine VCEK-signed evidence from zone {blob['zone']}")
        relayed = None
        for step in blob["chain"]:
            relayed, why = m.present(cl.peer_identity_key, cl.session_context, cl.exporter, as_evidence(step))
            print(f"   relayed counter {step['counter']}: accepted={relayed}  {why}")
            if not relayed: break
    out["relay_accepted"] = relayed
    out["exporters"] = note
    if "guest_side" in note:
        print(f"   guest-side exporter {note['guest_side'][:16]} != client-side {note['client_side'][:16]}")

    print("\n--- mandate log ---")
    for e in m.log: print("   ", e)
    out["log"] = [list(map(str, e)) for e in m.log]
    json.dump(out, open(f"{OUT}/verdict.json", "w"), indent=1)
    good = out["direct_accepted"] is True and out["relay_accepted"] is False
    print(f"\n  direct accepted : {out['direct_accepted']}")
    print(f"  relay  accepted : {out['relay_accepted']}")
    print("\n  RESULT:", "relay stopped against real hardware" if good else "*** UNEXPECTED ***")
    print(f"  evidence -> {OUT}")
    return 0 if good else 1

if __name__ == "__main__": sys.exit(main())
