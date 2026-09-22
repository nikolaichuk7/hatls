#!/usr/bin/env python3
"""Reattestation freshness on real SEV-SNP silicon, with the draft's OWN binder.

draft-fossati-seat-early-attestation-07, Section 8.4, states the gap in prose:

    "an attester, whether malicious or due to an incorrect implementation, could resend
     Evidence generated earlier in the connection in response to a later reattestation
     request, since the binder still matches and the Relying Party has no way to
     distinguish it from fresh Evidence."
    "... The mechanism will be defined in future revisions."

This run measures both halves on a real confidential VM, with real AMD-signed Evidence,
nothing forged:

  A. THE DRAFT'S BINDER, computed exactly as Section 5.1.1 defines it -- from this
     connection's real ClientHello..ServerHello transcript, the server's SubjectPublicKeyInfo,
     the cipher suite's hash and the "tls13 " label space (hatls/transcript.py; checked byte
     for byte against RFC 8448). The verifier computes it from ITS OWN recording of the wire,
     as Section 5.1.2 requires, and compares it to what the chip signed. The guest emits two
     genuine reports in one connection, both binding that one value. Then the Section 8.4
     attacker answers the round-1 request with round 0's report.

  B. THE CHAINED BINDER (this repository): post_link = HKDF(exporter, prev_link || counter).
     Same guest, same silicon. The same resend at step 1.

Neither part is an argument against early attestation. The chain sits on top of either
transport; what is measured is what a constant binder cannot tell apart, and what a
positioned one can.

Usage:  PYTHONPATH=. python3 examples/reattest_freshness_hw.py <guest-ip>
"""
import os, sys, json, base64, hashlib, socket, struct, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Mandate, report_data_for
from hatls.tee import sevsnp_verifier
from hatls.client import HatlsClient
from hatls import transcript as T

REPORT_DATA, MEASUREMENT, CHIP_ID, REPORT_ID = 0x50, 0x90, 0x1A0, 0x140
def field(rep, off, n): return rep[off:off+n]

def draft_binder_session(ip, steps):
    """One TLS 1.3 connection to the guest, recorded on our side; the guest's static-binder
    rounds; and the binder WE compute from what WE saw on the wire."""
    ctx = SSL.Context(SSL.TLS_METHOD); ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    sock = socket.create_connection((ip, 8443), timeout=60)
    c = T.BioConnection(ctx, sock, server=False); c.handshake()
    c.sendall(json.dumps({"static": True, "steps": steps, "binder": "draft-transcript"}).encode() + b"\n")
    n = struct.unpack(">I", c.recv_exact(4))[0]; blob = json.loads(c.recv_exact(n))
    ch, sh = T.transcript_ch_sh(c.sent, c.received)                      # our recording
    H = T.suite_hash(c.get_cipher_name())
    spki = x509.load_der_x509_certificate(
        crypto.dump_certificate(crypto.FILETYPE_ASN1, c.get_peer_certificate())
    ).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ours = T.draft_binder(ch, sh, spki, H)
    c.shutdown(); sock.close()
    return blob, ours, ch, sh, c.get_cipher_name()

def main(ip):
    verify = sevsnp_verifier(require_chain=True)
    OUT = f"evidence/reattest-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"; os.makedirs(OUT, exist_ok=True)
    print(f"guest {ip}:8443 — real AMD SEV-SNP confidential VM\nevidence -> {OUT}\n")

    # ------------------------------------------------------------ A. the draft's binder
    print("A. THE DRAFT'S BINDER  (draft-fossati-seat-early-attestation-07 Sec. 5.1.1, exact)")
    blob, ours, ch, sh, suite = draft_binder_session(ip, 2)
    rounds = blob["rounds"]
    r0, r1 = (base64.b64decode(rd["report"]) for rd in rounds)
    theirs = bytes.fromhex(rounds[0]["binder"])
    print(f"   instance                    {blob['instance']} @ {blob['zone']}")
    print(f"   suite / hash                {suite} / {T.suite_hash(suite)().name}")
    print(f"   ClientHello, ServerHello    {len(ch)} + {len(sh)} bytes, seen on OUR side of the wire")
    print(f"   transcript sha256 agrees    {hashlib.sha256(ch+sh).hexdigest() == blob['transcript_sha256']}")
    print(f"   binder, ours == guest's     {ours == theirs}   ({len(ours)} bytes, {ours.hex()[:24]}...)")
    if ours != theirs:
        print("   ABORT: the two ends disagree on the binder; nothing below is meaningful"); return 1

    # Section 5.1.2 verification: the binder we computed must be what the chip signed
    expect = T.binder_report_data(ours)
    ok0, anc0 = verify({"kind": "sev-snp", "report": rounds[0]["report"]}, expect)
    ok1, anc1 = verify({"kind": "sev-snp", "report": rounds[1]["report"]}, expect)
    print(f"   round 0 authentic + binds   {ok0}   (VCEK -> ASK -> ARK; REPORT_DATA == our binder)")
    print(f"   round 1 authentic + binds   {ok1}")
    if not (ok0 and ok1):
        print("   ABORT: a report failed appraisal"); return 1
    d0, d1 = field(r0, REPORT_DATA, 64), field(r1, REPORT_DATA, 64)
    print(f"   instance anchor             {anc0['instance'].hex()[:32]}...")
    print(f"   REPORT_DATA identical       {d0 == d1}")
    print(f"   whole report identical      {r0 == r1}   (signatures are randomised)")
    same = [nm for nm, o, l in (("MEASUREMENT", MEASUREMENT, 48), ("CHIP_ID", CHIP_ID, 64), ("REPORT_ID", REPORT_ID, 32))
            if field(r0, o, l) == field(r1, o, l)]
    print(f"   fields equal in both        {', '.join(same)}")
    accepted, _ = verify({"kind": "sev-snp", "report": rounds[0]["report"]}, expect)
    print(f"\n   Sec 8.4 attack: resend round 0's Evidence when round 1 is requested")
    print(f"   Sec 5.1.2 appraisal         {'ACCEPTED  <-- the gap, measured with their binder' if accepted else 'rejected'}")

    # ------------------------------------------------------------ B. the chained binder
    print("\nB. THE CHAINED BINDER  (this repository)")
    def as_evidence(step):
        return {"counter": step["counter"], "post_link": step["post_link"],
                "evidence": {"kind": "sev-snp", "report": step["report"],
                             "report_data": report_data_for(bytes.fromhex(step["post_link"])).hex()}}
    m = Mandate(verify, require_anchor=True)
    with HatlsClient(ip, 8443) as c:
        exporter, sc, tik = c.exporter, c.session_context, c.peer_identity_key
        chain = c.request({"steps": 2})["chain"]
    ok0, why0 = m.present(tik, sc, exporter, as_evidence(chain[0])); print(f"   step 0, fresh link          {'accepted' if ok0 else 'rejected'}: {why0}")
    ok1, why1 = m.present(tik, sc, exporter, as_evidence(chain[1])); print(f"   step 1, fresh link          {'accepted' if ok1 else 'rejected'}: {why1}")
    m2 = Mandate(verify, require_anchor=True); m2.present(tik, sc, exporter, as_evidence(chain[0]))
    okR, whyR = m2.present(tik, sc, exporter, as_evidence(chain[0]))
    print(f"\n   Sec 8.4 attack: resend step 0's Evidence when step 1 is requested")
    print(f"   chained appraisal           {'ACCEPTED' if okR else 'REJECTED'}: {whyR}")

    # ------------------------------------------------------------ evidence
    for i, rd in enumerate(rounds): open(f"{OUT}/draft-binder-round{i}.bin", "wb").write(base64.b64decode(rd["report"]))
    for st in chain: open(f"{OUT}/chain-c{st['counter']}.bin", "wb").write(base64.b64decode(st["report"]))
    open(f"{OUT}/client-hello.bin", "wb").write(ch); open(f"{OUT}/server-hello.bin", "wb").write(sh)
    json.dump({"guest": blob["instance"], "zone": blob["zone"],
               "draft_binder": {"suite": suite, "binder": ours.hex(), "guest_binder": theirs.hex(),
                                "transcript_sha256": hashlib.sha256(ch+sh).hexdigest(),
                                "report_data_round0": d0.hex(), "report_data_round1": d1.hex(),
                                "report_data_identical": d0 == d1, "reports_byte_identical": r0 == r1,
                                "stale_evidence_accepted": bool(accepted)},
               "chained_binder": {"step0": why0, "step1": why1, "stale_evidence_accepted": bool(okR), "reason": whyR}},
              open(f"{OUT}/verdict.json", "w"), indent=2)
    print("\nRESULT")
    print(f"   the draft's binder, stale Evidence at reattestation:  {'accepted' if accepted else 'rejected'}")
    print(f"   the chained binder, stale Evidence at reattestation:  {'accepted' if okR else 'rejected'}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
