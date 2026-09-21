#!/bin/bash
set -u
exec > /root/probe.log 2>&1
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
python3 - "$IID" "$AZ" <<'PY' > /dev/console 2>/root/py.log
import sys, os, fcntl, ctypes, hashlib, hmac, base64, json
IID, AZ = sys.argv[1], sys.argv[2]
NONCE = bytes.fromhex("d8d3aa6cc0d9bab3b4376cc9e29bb8c1073e71e676a923242aea5155e1a6fd22"); CSR = bytes.fromhex("3081d2307b02010030193117301506035504030c0e6861746c732d6964656e746974793059301306072a8648ce3d020106082a8648ce3d03010703420004c82fc951983dee0cdec6acc5e8a5fa62c38ebc3d94f2a62c43b19dea06c80e9709fd67f2668f217b5ecc415a9f6319a5ee9bd7eedb73fc17815b605c9e6fe36aa000300a06082a8648ce3d040302034700304402205ad4f0489e2555764837e91a1e595c785e0d4f7642db93bc676f98570e379b1b02207ac1404dd4b19110c83cbda70818b23cc2bcbc6d5b509084d881d0fa11e689c6")
EXPORTER = bytes.fromhex("52584424ef0a1d53d3464268302f913821ac74d71443e686af3c3df72fc3c79b"); SCTX = bytes.fromhex("fb8933dd88dccf4ec53379a3209d7a57aef83905f30b4c04512a25f7e92bdae2674fa8876b3890cf962702ddd10c0e07")
TIK = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004c82fc951983dee0cdec6acc5e8a5fa62c38ebc3d94f2a62c43b19dea06c80e9709fd67f2668f217b5ecc415a9f6319a5ee9bd7eedb73fc17815b605c9e6fe36a")
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
def snp_ext(user_data, buflen=32768):
    """SNP_GET_EXT_REPORT: the report AND the host certificate table. On a VLEK-signed platform
    the leaf lives only here -- AMD does not publish it by CHIP_ID -- so without this a verifier
    has nothing to check the signature against."""
    req=ExtReq(); ctypes.memmove(req.data.user_data,user_data,64); req.data.vmpl=0; req.data.flags=0
    buf=(ctypes.c_ubyte*buflen)()
    req.certs_address=ctypes.addressof(buf); req.certs_len=buflen
    resp=Resp(); io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR)
    try: fcntl.ioctl(fd,0xC0205302,io)
    finally: os.close(fd)
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError("fw %d"%resp.status)
    return bytes(resp.report[:1184]), bytes(buf[:min(req.certs_len,buflen)])
def snp(user_data):
    req=Req(); ctypes.memmove(req.user_data,user_data,64); req.vmpl=0; req.flags=0; resp=Resp()
    io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR); fcntl.ioctl(fd,0xC0205300,io); os.close(fd)
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError("fw %d"%resp.status)
    return bytes(resp.report[:1184])
pl = post(EXPORTER, intra(SCTX, TIK), 0)
try:
    enrol_rep, certs = snp_ext(hashlib.sha512(NONCE+CSR).digest())
except Exception as e:
    enrol_rep, certs = snp(hashlib.sha512(NONCE+CSR).digest()), b""
out = {"instance": IID, "az": AZ,
       "enrol": base64.b64encode(enrol_rep).decode(),
       "certs": certs.hex(),
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
