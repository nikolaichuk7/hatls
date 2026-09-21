#!/bin/bash
set -u
exec > /root/probe.log 2>&1
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
python3 - "$IID" "$AZ" <<'PY' > /dev/console 2>/root/py.log
import sys, os, fcntl, ctypes, hashlib, hmac, base64, json
IID, AZ = sys.argv[1], sys.argv[2]
NONCE = bytes.fromhex("3f5890a32be977974f3b66facba84093101095f2e3a7bd6e624bc9fdaf8d4876"); CSR = bytes.fromhex("3081d3307b02010030193117301506035504030c0e6861746c732d6964656e746974793059301306072a8648ce3d020106082a8648ce3d03010703420004152a2d47f80489238a89937b76a2cb2b165b37eb2584f848567624f6f83eca037a68297d0e5731c67e7144ffe7ba39dc4ca2a983c4dc3107d06820c41364d907a000300a06082a8648ce3d0403020348003045022067ccd7c4252dcd06a75ee72bccc4f2110d9a0715e97f39f787f98f0177113e20022100a8e9ca9b69a1359bf2888ee9636a70198e4c632fa6c2260c1208fd91a4cea6d0")
EXPORTER = bytes.fromhex("956c41c64a34b3aa5e72faedfa8658b5b1a035d47f00e1dcc236d349af184beb"); SCTX = bytes.fromhex("0a1c85eb919bb20b6cf1b9cb89243c0a43a5476e721d3ae4c1f17b62f8204843eb0c94c7353c4510e637a0b3e12058cb")
TIK = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004152a2d47f80489238a89937b76a2cb2b165b37eb2584f848567624f6f83eca037a68297d0e5731c67e7144ffe7ba39dc4ca2a983c4dc3107d06820c41364d907")
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
