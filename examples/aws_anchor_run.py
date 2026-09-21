#!/usr/bin/env python3
"""Does the instance anchor really work where the silicon anchor is gone? AWS, live.

The archive said `CHIP_ID` is all zeros on AWS shared tenancy across six instances, that the VLEK
signing key is shared region-wide, and that `REPORT_ID` is nonetheless distinct for every one of
them. That is an argument from stored bytes. This runs it on machines launched now.

AWS SEV-SNP guests here have no inbound network -- no security group is opened and no key pair is
installed -- so they report through the serial console, which is how our earlier RATS probes
worked. That costs one thing, and it is stated rather than hidden: **the exporter and session
context are supplied to the guest rather than derived from a live TLS handshake.** So this run
proves the anchor behaviour on live masked hardware; the TLS binding is what the GCP runs prove.

Usage:  PYTHONPATH=. python3 examples/aws_anchor_run.py [--keep]
"""
import base64, hashlib, json, os, subprocess, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import (Mandate, make_enrolment_csr, intra_link, post_link,
                            report_data_for)
from hatls.tee import sevsnp_verifier, parse_snp, snp_anchor

AZS = [("us-east-2", "us-east-2a"), ("eu-west-1", "eu-west-1a")]
TYPE = "m6a.large"
AMI_PARAM = "al2023-ami-kernel-6.1-x86_64"   # kernel 6.18 shut itself down under SEV-SNP, 11 Sep

def aws(*args, region=None):
    cmd = ["aws"] + (["--region", region] if region else []) + list(args)
    env = dict(os.environ, AWS_PAGER="")
    out = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{out.stderr.strip()[:400]}")
    return out.stdout.strip()

PROBE = r'''#!/bin/bash
set -u
exec > /root/probe.log 2>&1
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
python3 - "$IID" "$AZ" <<'PY' > /dev/console 2>/root/py.log
import sys, os, fcntl, ctypes, hashlib, hmac, base64, json
IID, AZ = sys.argv[1], sys.argv[2]
NONCE = bytes.fromhex("__NONCE__"); CSR = bytes.fromhex("__CSR__")
EXPORTER = bytes.fromhex("__EXPORTER__"); SCTX = bytes.fromhex("__SCTX__")
TIK = bytes.fromhex("__TIK__")
def hkdf_expand_label(secret, label, ctx, n=32):
    full=b"EXPERIMENTAL-hatls "+label
    info=n.to_bytes(2,"big")+bytes([len(full)])+full+bytes([len(ctx)])+ctx
    out=t=b""; i=1
    while len(out)<n: t=hmac.new(secret,t+info+bytes([i]),hashlib.sha384).digest(); out+=t; i+=1
    return out[:n]
def intra(th,tik):
    base=hkdf_expand_label(bytes(48),b"attestation base",th,48)
    return hkdf_expand_label(base,b"attestation",hashlib.sha384(tik).digest(),32)
def post(exp,prev,counter):
    return hkdf_expand_label(exp,b"continuity",prev+counter.to_bytes(8,"big"),32)
class Req(ctypes.Structure):  _fields_=[("user_data",ctypes.c_ubyte*64),("vmpl",ctypes.c_uint32),("flags",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24)]
class Resp(ctypes.Structure): _fields_=[("status",ctypes.c_uint32),("report_size",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24),("report",ctypes.c_ubyte*4000)]
class Io(ctypes.Structure):   _fields_=[("msg_version",ctypes.c_ubyte),("req_data",ctypes.c_uint64),("resp_data",ctypes.c_uint64),("exitinfo2",ctypes.c_uint64)]
class ExtReq(ctypes.Structure): _fields_=[("data",Req),("certs_address",ctypes.c_uint64),("certs_len",ctypes.c_uint32)]
SEV_FW_BLOB_MAX = 16384          # the kernel's SEV_FW_BLOB_MAX_SIZE
def snp_ext(user_data, buflen=SEV_FW_BLOB_MAX, probe_size=False):
    """SNP_GET_EXT_REPORT: the report AND the host certificate table. On a VLEK-signed platform
    the leaf lives only here -- AMD does not publish it by CHIP_ID -- so without this a verifier
    has nothing to check the signature against.

    The 6.1 driver rejects certs_len that is larger than SEV_FW_BLOB_MAX_SIZE or not page-aligned,
    with EINVAL and no explanation. Measured on Amazon Linux 2023, kernel 6.1.186."""
    buflen = min(max(buflen, 4096), SEV_FW_BLOB_MAX)
    buflen -= buflen % 4096
    req=ExtReq(); ctypes.memmove(req.data.user_data,user_data,64); req.data.vmpl=0; req.data.flags=0
    if probe_size:
        req.certs_address=0; req.certs_len=0; buf=None
    else:
        buf=(ctypes.c_ubyte*buflen)()
        req.certs_address=ctypes.addressof(buf); req.certs_len=buflen
    resp=Resp(); io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR)
    try: fcntl.ioctl(fd,0xC0205302,io)
    finally: os.close(fd)
    if probe_size: return None, req.certs_len
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError("fw %d"%resp.status)
    return bytes(resp.report[:1184]), bytes(buf[:min(req.certs_len,buflen)])
def snp(user_data):
    req=Req(); ctypes.memmove(req.user_data,user_data,64); req.vmpl=0; req.flags=0; resp=Resp()
    io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR); fcntl.ioctl(fd,0xC0205300,io); os.close(fd)
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError("fw %d"%resp.status)
    return bytes(resp.report[:1184])
pl = post(EXPORTER, intra(SCTX, TIK), 0)
RD = hashlib.sha512(NONCE+CSR).digest()
VLEK_GUID = "c24b07a85aa23e48aae639c045a0b8a1"   # AMD a8074bc2-a25a-483e-aae6-39c045a0b8a1
def pick_leaf(blob):
    """Walk the GHCB certificate table here on the guest and return ONLY the VLEK leaf.

    The whole table is 16 KiB, and pushing that through a serial console is how the transfer
    breaks. One certificate is 1-2 KiB."""
    off=0; inv=[]; leaf=b""
    while off+24 <= len(blob):
        guid=blob[off:off+16]
        o=int.from_bytes(blob[off+16:off+20],"little"); l=int.from_bytes(blob[off+20:off+24],"little")
        if guid==bytes(16): break
        if l and o+l<=len(blob):
            inv.append("%s:%d"%(guid.hex()[:8], l))
            if guid.hex()==VLEK_GUID: leaf=blob[o:o+l]
        off+=24
    if not leaf:                                  # fall back to the first thing shaped like DER
        for g,l2 in []: pass
        off=0
        while off+24 <= len(blob):
            guid=blob[off:off+16]
            o=int.from_bytes(blob[off+16:off+20],"little"); l=int.from_bytes(blob[off+20:off+24],"little")
            if guid==bytes(16): break
            if l and o+l<=len(blob) and blob[o:o+1]==b"\x30" and 600<l<3000:
                leaf=blob[o:o+l]; break
            off+=24
    return leaf, inv
certs=b""; notes=[]
try:
    enrol_rep, certs = snp_ext(RD)
    notes.append("ext direct ok len=%d"%len(certs))
except Exception as e:
    notes.append("ext direct failed: %r"%(e,))
    try:                                        # the kernel reports the size it wants, then we retry
        _, need = snp_ext(RD, probe_size=True)
        notes.append("kernel asked for %d bytes"%need)
        enrol_rep, certs = snp_ext(RD, buflen=need)
        notes.append("ext two-step ok len=%d"%len(certs))
    except Exception as e2:
        notes.append("ext two-step failed: %r"%(e2,))
        enrol_rep = snp(RD)
try: notes.append("kernel "+open("/proc/version").read().split()[2])
except Exception: pass
leaf_der, inv = pick_leaf(certs)
notes.append("table entries %s; leaf %d bytes"%(",".join(inv) or "none", len(leaf_der)))
out = {"instance": IID, "az": AZ,
       "enrol": base64.b64encode(enrol_rep).decode(),
       "leaf": leaf_der.hex(), "table": inv, "notes": notes,
       "post_link": pl.hex(),
       "step": base64.b64encode(snp(hashlib.sha512(b"HATLS-continuity-v0"+pl).digest())).decode()}
# The serial console interleaves its own lines into anything long, and base64 quietly survives
# that by discarding the intruding characters -- producing plausible bytes of the wrong length.
# So: fixed-width numbered chunks the reader can pick out exactly, and a digest that makes a
# damaged transfer fail loudly instead of decoding into nonsense.
payload = json.dumps(out, sort_keys=True).encode()
hx = payload.hex()
CH = 256
print("HATLSMETA %s %s %d %s" % (IID, AZ, (len(hx)+CH-1)//CH, hashlib.sha256(payload).hexdigest()))
for i in range(0, len(hx), CH):
    print("HATLSC %04d %s" % (i//CH, hx[i:i+CH].ljust(CH, "0") if i+CH > len(hx) else hx[i:i+CH]))
print("HATLSLEN %d" % len(hx))
print("HATLSEND")
PY
'''

def certs_from_table(blob):
    """The GHCB host certificate table: 16-byte GUID, u32 offset, u32 length, zero-GUID terminator."""
    out = []
    off = 0
    while off + 24 <= len(blob):
        guid = blob[off:off+16]
        o = int.from_bytes(blob[off+16:off+20], "little")
        l = int.from_bytes(blob[off+20:off+24], "little")
        if guid == bytes(16): break
        if l and o + l <= len(blob): out.append((guid.hex(), blob[o:o+l]))
        off += 24
    return out

def vlek_pem(leaf_hex):
    """The guest already picked the leaf out of the table; turn it into PEM if it parses."""
    from cryptography import x509 as _x
    from cryptography.hazmat.primitives import serialization as _ser
    if not leaf_hex: return None
    data = bytes.fromhex(leaf_hex)
    try:
        cert = (_x.load_pem_x509_certificate(data) if data[:11] == b"-----BEGIN "
                else _x.load_der_x509_certificate(data))
    except Exception:
        return None
    return cert.public_bytes(_ser.Encoding.PEM).decode()

def reassemble(console_text):
    """Pull our chunks out of whatever else the console printed, and refuse anything damaged."""
    import re
    meta = re.search(r"HATLSMETA (\S+) (\S+) (\d+) ([0-9a-f]{64})", console_text)
    ln = re.search(r"HATLSLEN (\d+)", console_text)
    if not meta or not ln: return None
    want, digest, hexlen = int(meta.group(3)), meta.group(4), int(ln.group(1))
    chunks = {int(n): h for n, h in re.findall(r"HATLSC (\d{4}) ([0-9a-f]{256})", console_text)}
    if len(chunks) != want: return None
    hx = "".join(chunks[i] for i in range(want))[:hexlen]
    try:
        payload = bytes.fromhex(hx)
    except ValueError:
        return None
    if hashlib.sha256(payload).hexdigest() != digest: return None
    return json.loads(payload)

def main():
    keep = "--keep" in sys.argv
    OUT = f"evidence/aws-anchor-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    os.makedirs(OUT, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    tik = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    m = Mandate(sevsnp_verifier())
    nonce = m.challenge(); csr = make_enrolment_csr(key)
    exporter, sctx = os.urandom(32), os.urandom(48)
    ud = (PROBE.replace("__NONCE__", nonce.hex()).replace("__CSR__", csr.hex())
              .replace("__EXPORTER__", exporter.hex()).replace("__SCTX__", sctx.hex())
              .replace("__TIK__", tik.hex()))
    udfile = os.path.join(OUT, "user-data.sh"); open(udfile, "w").write(ud)

    launched = []
    print("=== 1. LAUNCHING TWO AWS SEV-SNP INSTANCES IN DIFFERENT REGIONS ===")
    for region, az in AZS:
        ami = aws("ssm", "get-parameter", "--name",
                  f"/aws/service/ami-amazon-linux-latest/{AMI_PARAM}",
                  "--query", "Parameter.Value", "--output", "text", region=region)
        sub = aws("ec2", "describe-subnets", "--filters",
                  f"Name=availability-zone,Values={az}", "Name=default-for-az,Values=true",
                  "--query", "Subnets[0].SubnetId", "--output", "text", region=region)
        iid = aws("ec2", "run-instances", "--image-id", ami, "--instance-type", TYPE,
                  "--subnet-id", sub, "--count", "1", "--cpu-options", "AmdSevSnp=enabled",
                  "--user-data", f"file://{udfile}",
                  "--metadata-options", "HttpTokens=required,HttpEndpoint=enabled",
                  "--tag-specifications",
                  "ResourceType=instance,Tags=[{Key=Name,Value=hatls-anchor},{Key=purpose,Value=hatls-instance-anchor}]",
                  "--query", "Instances[0].InstanceId", "--output", "text", region=region)
        print(f"   {az}: {iid}")
        launched.append((region, az, iid))

    print("\n=== 2. WAITING FOR THE PROBES ON THE SERIAL CONSOLE ===")
    results = {}
    deadline = time.time() + 900
    while time.time() < deadline and len(results) < len(launched):
        for region, az, iid in launched:
            if iid in results: continue
            try:
                txt = aws("ec2", "get-console-output", "--instance-id", iid, "--latest",
                          "--output", "text", region=region)
            except Exception:
                continue
            if "HATLSEND" not in txt: continue
            parsed = reassemble(txt)
            if parsed is None:
                print(f"   {az}: output present but incomplete or corrupt; still waiting")
                continue
            results[iid] = parsed
            print(f"   {az}: report received and digest verified")
        if len(results) < len(launched): time.sleep(20)
    json.dump(results, open(f"{OUT}/probes.json", "w"), indent=1)
    if len(results) < 2:
        print(f"   only {len(results)} of 2 reported; see {OUT}")
        if not keep: terminate(launched)
        return 1

    print("\n=== 3. WHAT THE LIVE REPORTS SAY ===")
    claims = {}
    for iid, r in results.items():
        f = parse_snp(base64.b64decode(r["enrol"])); a = snp_anchor(f)
        claims[iid] = {"az": r["az"], "signing_key": f["signing_key"],
                       "chip_zero": f["chip_id_zero"], "mask_flag": bool(f["mask_chip_key"]),
                       "instance": a["instance"].hex(), "place": a["place"].hex() if a["place"] else None}
        c = claims[iid]
        print(f"   {r['az']:12} {iid}")
        print(f"      signing key {c['signing_key']}   CHIP_ID all zero: {c['chip_zero']}   "
              f"MASK_CHIP_KEY flag: {c['mask_flag']}")
        print(f"      instance (REPORT_ID) {c['instance'][:16]}   place {c['place'] or 'ABSENT'}")
    ids = list(results)
    distinct = claims[ids[0]]["instance"] != claims[ids[1]]["instance"]
    both_masked = all(c["chip_zero"] for c in claims.values())
    print(f"\n   both have NO silicon claim : {both_masked}")
    print(f"   instance claims differ     : {distinct}")

    print("\n=== 4. THE MANDATE, ON THESE LIVE REPORTS ===")
    A, B = ids[0], ids[1]
    leaf = {i: vlek_pem(results[i].get("leaf")) for i in ids}
    for i in ids:
        for n in results[i].get("notes", []): print(f"   [{claims[i]['az']}] {n}")
        print(f"   VLEK leaf from {claims[i]['az']} host certificate table: "
              f"{'present' if leaf[i] else 'ABSENT'}")
    ev = {"kind": "sev-snp", "report": results[A]["enrol"], "leaf_pem": leaf[A],
          "report_data": hashlib.sha512(nonce + csr).digest().hex()}
    okA, whyA = m.enroll(tik, ev, nonce, csr)
    print(f"   enrol {claims[A]['az']}: {okA} ({whyA})")
    def step(iid):
        pl = bytes.fromhex(results[iid]["post_link"])
        return {"counter": 0, "post_link": results[iid]["post_link"],
                "evidence": {"kind": "sev-snp", "report": results[iid]["step"],
                             "leaf_pem": leaf[iid],
                             "report_data": report_data_for(pl).hex()}}
    okB, whyB = m.present(tik, sctx, exporter, step(B))
    print(f"   present {claims[B]['az']} (same key, other instance): {okB}")
    print(f"     -> {whyB}")
    okA2, whyA2 = m.present(tik, sctx, exporter, step(A))
    print(f"   present {claims[A]['az']} (the enrolled one): {okA2} ({whyA2})")

    verdict = {"claims": claims, "both_masked": both_masked, "instances_differ": distinct,
               "enrolled": okA, "impostor_refused": okB is False, "owner_accepted": okA2 is True,
               "log": [list(map(str, e)) for e in m.log]}
    json.dump(verdict, open(f"{OUT}/verdict.json", "w"), indent=1)
    good = both_masked and distinct and okA and (okB is False) and (okA2 is True)
    print(f"\n  RESULT: {'the instance anchor works where the silicon anchor is gone' if good else '*** UNEXPECTED ***'}")
    print(f"  evidence -> {OUT}")
    if not keep: terminate(launched)
    return 0 if good else 1

def terminate(launched):
    print("\n=== 5. TERMINATING ===")
    for region, az, iid in launched:
        try:
            aws("ec2", "terminate-instances", "--instance-ids", iid,
                "--query", "TerminatingInstances[0].CurrentState.Name", "--output", "text",
                region=region)
            print(f"   {az}: {iid} terminating")
        except Exception as e:
            print(f"   {az}: {iid} TERMINATE FAILED -- do it by hand: {e}")

if __name__ == "__main__": sys.exit(main())
