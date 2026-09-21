#!/usr/bin/env python3
"""The third cloud: Azure confidential VMs, AMD SEV-SNP.

GCP proved the full cycle including the TLS binding. AWS proved the instance anchor on shared
tenancy, where CHIP_ID is zeroed and the VLEK signing key is shared region-wide. Azure is the
remaining platform the review named, and the question is the same one: does the mandate anchor on
the instance correctly here, and can the verifier appraise the evidence at all?

Same shape as the AWS run. These VMs are created with no public address and no inbound rule, so
they report through the boot serial log, and the exporter and session context are supplied rather
than derived from a live handshake -- the relay defence is what the GCP runs prove, not this.

Usage:  PYTHONPATH=. python3 examples/azure_anchor_run.py [--keep]
"""
import hashlib, json, os, re, subprocess, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from hatls.protocol import Mandate, make_enrolment_csr, report_data_for
from hatls.tee import sevsnp_verifier, parse_snp, snp_anchor

RG = "hatls-anchor-rg"
IMAGE = "Canonical:ubuntu-24_04-lts:cvm:latest"
SIZE = "Standard_DC2ads_v5"
PLACES = [("eastus", "az-a"), ("GermanyWestCentral", "az-b")]

def az(*args, timeout=900):
    out = subprocess.run(["az"] + list(args), capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError(f"az {' '.join(args[:4])}\n{out.stderr.strip()[:400]}")
    return out.stdout.strip()

PROBE = r'''#!/bin/bash
exec > /var/log/hatls.log 2>&1
set -x
python3 - <<'PY' > /dev/console 2>>/var/log/hatls.log
import os, fcntl, ctypes, hashlib, hmac, base64, json, socket
NONCE=bytes.fromhex("__NONCE__"); CSR=bytes.fromhex("__CSR__")
EXPORTER=bytes.fromhex("__EXPORTER__"); SCTX=bytes.fromhex("__SCTX__"); TIK=bytes.fromhex("__TIK__")
def hkdf_expand_label(secret,label,ctx,n=32):
    full=b"EXPERIMENTAL-hatls "+label
    info=n.to_bytes(2,"big")+bytes([len(full)])+full+bytes([len(ctx)])+ctx
    out=t=b""; i=1
    while len(out)<n: t=hmac.new(secret,t+info+bytes([i]),hashlib.sha384).digest(); out+=t; i+=1
    return out[:n]
def intra(th,tik):
    base=hkdf_expand_label(bytes(48),b"attestation base",th,48)
    return hkdf_expand_label(base,b"attestation",hashlib.sha384(tik).digest(),32)
def post(exp,prev,c): return hkdf_expand_label(exp,b"continuity",prev+c.to_bytes(8,"big"),32)
class Req(ctypes.Structure):  _fields_=[("user_data",ctypes.c_ubyte*64),("vmpl",ctypes.c_uint32),("flags",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24)]
class Resp(ctypes.Structure): _fields_=[("status",ctypes.c_uint32),("report_size",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24),("report",ctypes.c_ubyte*4000)]
class Io(ctypes.Structure):   _fields_=[("msg_version",ctypes.c_ubyte),("req_data",ctypes.c_uint64),("resp_data",ctypes.c_uint64),("exitinfo2",ctypes.c_uint64)]
class ExtReq(ctypes.Structure): _fields_=[("data",Req),("certs_address",ctypes.c_uint64),("certs_len",ctypes.c_uint32)]
VLEK_GUID="c24b07a85aa23e48aae639c045a0b8a1"
def snp(ud):
    req=Req(); ctypes.memmove(req.user_data,ud,64); resp=Resp()
    io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR)
    try: fcntl.ioctl(fd,0xC0205300,io)
    finally: os.close(fd)
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError("fw %d"%resp.status)
    return bytes(resp.report[:1184])
def snp_ext(ud,buflen=16384):
    buflen=min(max(buflen,4096),16384); buflen-=buflen%4096
    req=ExtReq(); ctypes.memmove(req.data.user_data,ud,64)
    buf=(ctypes.c_ubyte*buflen)(); req.certs_address=ctypes.addressof(buf); req.certs_len=buflen
    resp=Resp(); io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR)
    try: fcntl.ioctl(fd,0xC0205302,io)
    finally: os.close(fd)
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError("fw %d"%resp.status)
    return bytes(resp.report[:1184]), bytes(buf[:min(req.certs_len,buflen)])
def pick_leaf(blob):
    off=0; inv=[]; leaf=b""
    while off+24<=len(blob):
        guid=blob[off:off+16]
        o=int.from_bytes(blob[off+16:off+20],"little"); l=int.from_bytes(blob[off+20:off+24],"little")
        if guid==bytes(16): break
        if l and o+l<=len(blob):
            inv.append("%s:%d"%(guid.hex()[:8],l))
            if guid.hex()==VLEK_GUID: leaf=blob[o:o+l]
        off+=24
    return leaf, inv
RD=hashlib.sha512(NONCE+CSR).digest(); notes=[]; certs=b""
try:
    enrol_rep, certs = snp_ext(RD); notes.append("ext ok certs=%d"%len(certs))
except Exception as e:
    notes.append("ext failed: %r"%(e,)); enrol_rep = snp(RD)
try: notes.append("kernel "+open("/proc/version").read().split()[2])
except Exception: pass
leaf, inv = pick_leaf(certs)
notes.append("table %s; leaf %d"%(",".join(inv) or "none", len(leaf)))
pl=post(EXPORTER,intra(SCTX,TIK),0)
out={"host":socket.gethostname(),"enrol":base64.b64encode(enrol_rep).decode(),
     "leaf":leaf.hex(),"post_link":pl.hex(),"notes":notes,
     "step":base64.b64encode(snp(hashlib.sha512(b"HATLS-continuity-v0"+pl).digest())).decode()}
payload=json.dumps(out,sort_keys=True).encode(); hx=payload.hex(); CH=256
print("HATLSMETA %s azure %d %s"%(out["host"],(len(hx)+CH-1)//CH,hashlib.sha256(payload).hexdigest()))
for _p in range(2):
    for i in range(0,len(hx),CH):
        c=hx[i:i+CH]
        print("HATLSC %04d %s"%(i//CH, c.ljust(CH,"0") if i+CH>len(hx) else c))
print("HATLSLEN %d"%len(hx)); print("HATLSEND")
PY
'''

def reassemble(txt):
    meta = re.search(r"HATLSMETA (\S+) (\S+) (\d+) ([0-9a-f]{64})", txt)
    ln = re.search(r"HATLSLEN (\d+)", txt)
    if not meta or not ln: return None
    want, digest, hexlen = int(meta.group(3)), meta.group(4), int(ln.group(1))
    chunks = {int(n): h for n, h in re.findall(r"HATLSC (\d{4}) ([0-9a-f]{256})", txt)}
    if len(chunks) != want: return None
    hx = "".join(chunks[i] for i in range(want))[:hexlen]
    try: payload = bytes.fromhex(hx)
    except ValueError: return None
    if hashlib.sha256(payload).hexdigest() != digest: return None
    return json.loads(payload)

def leaf_pem(h):
    from cryptography import x509 as _x
    from cryptography.hazmat.primitives import serialization as _s
    if not h: return None
    d = bytes.fromhex(h)
    try:
        c = _x.load_pem_x509_certificate(d) if d[:11] == b"-----BEGIN " else _x.load_der_x509_certificate(d)
    except Exception: return None
    return c.public_bytes(_s.Encoding.PEM).decode()

def main():
    keep = "--keep" in sys.argv
    OUT = f"evidence/azure-anchor-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
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
    udf = os.path.join(OUT, "cloud-init.sh"); open(udf, "w").write(ud)

    print("=== 1. TWO AZURE CONFIDENTIAL VMs, NO INBOUND ===")
    az("group", "create", "-n", RG, "-l", PLACES[0][0], "-o", "none")
    names = []
    for region, name in PLACES:
        az("vm", "create", "-g", RG, "-n", name, "-l", region, "--size", SIZE,
           "--image", IMAGE, "--security-type", "ConfidentialVM",
           "--os-disk-security-encryption-type", "VMGuestStateOnly",
           "--enable-vtpm", "true", "--enable-secure-boot", "true",
           "--public-ip-address", "", "--nsg", "", "--custom-data", udf,
           "--admin-username", "hatls", "--generate-ssh-keys", "-o", "none")
        print(f"   {name} in {region}: created")
        names.append(name)

    print("\n=== 2. WAITING FOR THE BOOT SERIAL LOG ===")
    got = {}
    deadline = time.time() + 1200
    while time.time() < deadline and len(got) < len(names):
        for n in names:
            if n in got: continue
            try:
                txt = az("vm", "boot-diagnostics", "get-boot-log", "-g", RG, "-n", n)
            except Exception:
                continue
            if "HATLSEND" not in txt: continue
            p = reassemble(txt)
            if p is None:
                print(f"   {n}: output present but incomplete; still waiting"); continue
            got[n] = p; print(f"   {n}: report received and digest verified")
        if len(got) < len(names): time.sleep(25)
    json.dump(got, open(f"{OUT}/probes.json", "w"), indent=1)
    if len(got) < 2:
        print(f"   only {len(got)} of 2 reported; see {OUT}")
        if not keep: cleanup()
        return 1

    print("\n=== 3. WHAT THE LIVE REPORTS SAY ===")
    claims = {}
    for n, r in got.items():
        for note in r["notes"]: print(f"   [{n}] {note}")
        f = parse_snp(__import__("base64").b64decode(r["enrol"])); a = snp_anchor(f)
        claims[n] = {"signing_key": f["signing_key"], "chip_zero": f["chip_id_zero"],
                     "mask": bool(f["mask_chip_key"]), "instance": a["instance"].hex(),
                     "place": a["place"].hex() if a["place"] else None}
        c = claims[n]
        print(f"   {n}: signing key {c['signing_key']}  CHIP_ID zero {c['chip_zero']}  "
              f"MASK flag {c['mask']}")
        print(f"      instance {c['instance'][:16]}   place {(c['place'] or 'ABSENT')[:16]}")
    ns = list(got)
    diff_i = claims[ns[0]]["instance"] != claims[ns[1]]["instance"]
    diff_p = claims[ns[0]]["place"] != claims[ns[1]]["place"]
    print(f"\n   instance claims differ : {diff_i}")
    print(f"   place claims differ    : {diff_p}")

    print("\n=== 4. THE MANDATE, ON THESE LIVE REPORTS ===")
    A, B = ns[0], ns[1]
    leaf = {n: leaf_pem(got[n].get("leaf")) for n in ns}
    ev = {"kind": "sev-snp", "report": got[A]["enrol"], "leaf_pem": leaf[A],
          "report_data": hashlib.sha512(nonce + csr).digest().hex()}
    okA, whyA = m.enroll(tik, ev, nonce, csr)
    print(f"   enrol {A}: {okA} ({whyA})")
    def step(n):
        pl = bytes.fromhex(got[n]["post_link"])
        return {"counter": 0, "post_link": got[n]["post_link"],
                "evidence": {"kind": "sev-snp", "report": got[n]["step"], "leaf_pem": leaf[n],
                             "report_data": report_data_for(pl).hex()}}
    okB, whyB = m.present(tik, sctx, exporter, step(B))
    print(f"   present {B} (same key, other instance): {okB}")
    print(f"     -> {whyB}")
    okA2, whyA2 = m.present(tik, sctx, exporter, step(A))
    print(f"   present {A} (the enrolled one): {okA2} ({whyA2})")

    v = {"claims": claims, "instances_differ": diff_i, "places_differ": diff_p,
         "enrolled": okA, "impostor_refused": okB is False, "owner_accepted": okA2 is True,
         "log": [list(map(str, e)) for e in m.log]}
    json.dump(v, open(f"{OUT}/verdict.json", "w"), indent=1)
    good = diff_i and okA and (okB is False) and (okA2 is True)
    print(f"\n  RESULT: {'the mandate works on Azure confidential VMs' if good else '*** UNEXPECTED ***'}")
    print(f"  evidence -> {OUT}")
    if not keep: cleanup()
    return 0 if good else 1

def cleanup():
    print("\n=== 5. DELETING THE RESOURCE GROUP ===")
    try:
        az("group", "delete", "-n", RG, "--yes", "--no-wait", "-o", "none")
        print(f"   {RG}: delete requested (no-wait)")
    except Exception as e:
        print(f"   {RG}: DELETE FAILED -- do it by hand: {e}")

if __name__ == "__main__": sys.exit(main())
