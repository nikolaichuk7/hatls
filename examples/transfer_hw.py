#!/usr/bin/env python3
"""Owner-authorised transfer on live SEV-SNP hardware.

The sequence the mandate requires, end to end on real silicon:

  1. guest A enrols, naming an owner key as its transfer authority;
  2. guest B -- same stolen identity key, different instance -- attests and is REFUSED, which is
     also the moment the mandate witnesses that B exists;
  3. the owner issues a single-use, time-bounded grant naming the instance being left and the
     witnessed instance to move to;
  4. B now carries the identity, A does not, and the grant cannot be used again.

Identity here is the instance claim (REPORT_ID), not the silicon: the mandate is proving that a
particular confidential VM holds the key, which CHIP_ID cannot express.

Usage:  PYTHONPATH=. python3 examples/transfer_hw.py <ip-a> <ip-b>
"""
import json, base64, hashlib, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from hatls.protocol import Mandate, report_data_for, csr_public_key_der
from hatls.tee import sevsnp_verifier, parse_snp, snp_anchor
from hatls.client import HatlsClient
from hatls.transfer import make_grant, authority_public_bytes

def step(blob):
    s = blob["chain"][0]
    return {"counter": 0, "post_link": s["post_link"],
            "evidence": {"kind": "sev-snp", "report": s["report"],
                         "report_data": report_data_for(bytes.fromhex(s["post_link"])).hex()}}

def claims(report_b64):
    a = snp_anchor(parse_snp(base64.b64decode(report_b64)))
    return a["instance"], (a["place"].hex()[:16] if a["place"] else "masked")

def main():
    ipA, ipB = sys.argv[1], sys.argv[2]
    OUT = f"evidence/transfer-hw-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    os.makedirs(OUT, exist_ok=True)
    owner = ec.generate_private_key(ec.SECP256R1())
    m = Mandate(sevsnp_verifier())
    out = {}

    print(f"=== 1. ENROLMENT on guest A ({ipA}), owner key named as transfer authority ===")
    with HatlsClient(ipA, 8443) as cl:
        nonce = m.challenge()
        r = cl.request({"enroll": True, "nonce": nonce.hex()})
        json.dump(r, open(f"{OUT}/enrollA.json", "w"))
        csr = bytes.fromhex(r["csr"]); tik = cl.peer_identity_key
        assert csr_public_key_der(csr) == tik, "CSR does not carry the TLS peer key"
        ev = {"kind": "sev-snp", "report": r["report"],
              "report_data": hashlib.sha512(nonce + csr).digest().hex()}
        ok, why = m.enroll(tik, ev, nonce, csr, transfer_authority=authority_public_bytes(owner))
        instA, placeA = claims(r["report"])
        print(f"   zone {r['zone']}  instance {instA.hex()[:16]}  place {placeA}")
        print(f"   enrolled={ok} ({why})")
        out["enrolled"] = ok; out["instance_a"] = instA.hex(); out["place_a"] = placeA
        if not ok: return 1

    print(f"\n=== 2. GUEST B ({ipB}) holds the same key: refused, and witnessed ===")
    with HatlsClient(ipB, 8443) as cl:
        blob = cl.request({"steps": 1}); json.dump(blob, open(f"{OUT}/guestB.json", "w"))
        instB, placeB = claims(blob["chain"][0]["report"])
        okB, whyB = m.present(tik, cl.session_context, cl.exporter, step(blob))
        print(f"   zone {blob['zone']}  instance {instB.hex()[:16]}  place {placeB}")
        print(f"   accepted={okB}  {whyB}")
        out["instance_b"] = instB.hex(); out["place_b"] = placeB; out["b_refused_before"] = not okB
    witnessed = [w["instance"] for w in m._rec(tik.hex())["witnessed"]]
    print(f"   the mandate now witnesses {len(witnessed)} instance(s); B among them: "
          f"{instB.hex() in witnessed}")

    print("\n=== 3. THE OWNER AUTHORISES THE MOVE ===")
    grant, sig = make_grant(owner, tik, instB, from_instance=instA, valid_for=300)
    ok, why = m.accept_transfer(tik, grant, sig)
    print(f"   grant {grant['nonce'][:12]}  from {instA.hex()[:16]} -> to {instB.hex()[:16]}")
    print(f"   accepted={ok} ({why})")
    out["transferred"] = ok
    json.dump({"grant": grant, "sig": sig.hex()}, open(f"{OUT}/grant.json", "w"))

    print("\n=== 4. AFTERWARDS ===")
    with HatlsClient(ipB, 8443) as cl:
        blob = cl.request({"steps": 1})
        okB2, whyB2 = m.present(tik, cl.session_context, cl.exporter, step(blob))
        print(f"   guest B now: accepted={okB2}  {whyB2}")
        out["b_accepted_after"] = okB2
    with HatlsClient(ipA, 8443) as cl:
        blob = cl.request({"steps": 1}); json.dump(blob, open(f"{OUT}/guestA-after.json", "w"))
        okA2, whyA2 = m.present(tik, cl.session_context, cl.exporter, step(blob))
        print(f"   guest A now: accepted={okA2}  {whyA2}")
        out["a_refused_after"] = not okA2
    ok3, why3 = m.accept_transfer(tik, grant, sig)
    print(f"   the same grant a second time: accepted={ok3} ({why3})")
    out["replay_refused"] = not ok3

    print("\n--- mandate log ---")
    for e in m.log: print("   ", e)
    out["log"] = [list(map(str, e)) for e in m.log]
    json.dump(out, open(f"{OUT}/verdict.json", "w"), indent=1)
    good = all([out["enrolled"], out["b_refused_before"], out["transferred"],
                out["b_accepted_after"], out["a_refused_after"], out["replay_refused"]])
    print(f"\n  RESULT: {'owner-authorised transfer verified on real SEV-SNP' if good else '*** UNEXPECTED ***'}")
    print(f"  evidence -> {OUT}")
    return 0 if good else 1

if __name__ == "__main__": sys.exit(main())
