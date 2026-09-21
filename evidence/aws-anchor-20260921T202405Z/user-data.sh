#!/bin/bash
set -u
exec > /root/probe.log 2>&1
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
python3 - "$IID" "$AZ" <<'PY' > /dev/console 2>/root/py.log
import sys, os, fcntl, ctypes, hashlib, hmac, base64, json
IID, AZ = sys.argv[1], sys.argv[2]
NONCE = bytes.fromhex("50362d76290991d6886eb5750e6533d4a457673a9aebc2dbca679027c4d811f8"); CSR = bytes.fromhex("3081d2307b02010030193117301506035504030c0e6861746c732d6964656e746974793059301306072a8648ce3d020106082a8648ce3d03010703420004ad0e53132256943c8bc1b4a839d615ff2c3ae2f74e14c391dcd22e47ef643dbd571e61f77198d4ff2e8d6e12d802ff8264198ab9f160762a4988869d06e6dd31a000300a06082a8648ce3d0403020347003044022058cfb05f80c3cf33b8c99e12a1ae583e314bcdf9e37a06113ec5a6e07309087f0220129c7e70e9078e0641af69b0dafdaac95fd8f2eb30229916b65b63e2b0d57d30")
EXPORTER = bytes.fromhex("24206db1ab96de40731a2e09d337a1f4b957e58920552aa30fd47fc7c2d536c1"); SCTX = bytes.fromhex("9058c4cdccd1b502b111924d4158c1e2f6e8947a42e86a5e7062319285dca66679f72cce2072698d57cf86a3cb70571a")
TIK = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004ad0e53132256943c8bc1b4a839d615ff2c3ae2f74e14c391dcd22e47ef643dbd571e61f77198d4ff2e8d6e12d802ff8264198ab9f160762a4988869d06e6dd31")
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
def snp(user_data):
    req=Req(); ctypes.memmove(req.user_data,user_data,64); req.vmpl=0; req.flags=0; resp=Resp()
    io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR); fcntl.ioctl(fd,0xC0205300,io); os.close(fd)
    if resp.status!=0 or resp.report_size!=1184: raise RuntimeError("fw %d"%resp.status)
    return bytes(resp.report[:1184])
pl = post(EXPORTER, intra(SCTX, TIK), 0)
out = {"instance": IID, "az": AZ,
       "enrol": base64.b64encode(snp(hashlib.sha512(NONCE+CSR).digest())).decode(),
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
