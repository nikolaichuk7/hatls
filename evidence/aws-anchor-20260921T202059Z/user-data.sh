#!/bin/bash
set -u
exec > /root/probe.log 2>&1
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
python3 - "$IID" "$AZ" <<'PY' > /dev/console 2>/root/py.log
import sys, os, fcntl, ctypes, hashlib, hmac, base64, json
IID, AZ = sys.argv[1], sys.argv[2]
NONCE = bytes.fromhex("0758e09e7c09ba42e6c9097a3758cc65c4010d44963159f4f75db2e16db355a1"); CSR = bytes.fromhex("3081d3307b02010030193117301506035504030c0e6861746c732d6964656e746974793059301306072a8648ce3d020106082a8648ce3d03010703420004b896cee43d370baac84c325373ad7d8975a3d127b314d9e22038dc3d2464981e7946ce78eae46aa0ed063e892492b54964927ec504f962db0f4628df7b2d6669a000300a06082a8648ce3d0403020348003045022100d00d6f84e251c56613a95565acfc8c3cbefd7c65b07504286c3d38a7ecb381dd022052e32d4dda417b62d65d918ee64aa2ec27d80e85b68b444f62b21d3e13bfe913")
EXPORTER = bytes.fromhex("be562c58107b12172e1b2dd3fa9eb3d3d3fea38ceb5878bd2a8b15a50de58c3f"); SCTX = bytes.fromhex("2a9ab0af075124924618ac08fda28c9f4d9e97f28bff140169cd05bf43d8fe43b97efc4241622dbfd14162caef93c022")
TIK = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004b896cee43d370baac84c325373ad7d8975a3d127b314d9e22038dc3d2464981e7946ce78eae46aa0ed063e892492b54964927ec504f962db0f4628df7b2d6669")
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
print("===HATLS-BEGIN===" + json.dumps(out) + "===HATLS-END===")
PY
