#!/bin/bash
set -u
exec > /root/probe.log 2>&1
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
python3 - "$IID" "$AZ" <<'PY' > /dev/console 2>/root/py.log
import sys, os, fcntl, ctypes, hashlib, hmac, base64, json
IID, AZ = sys.argv[1], sys.argv[2]
NONCE = bytes.fromhex("ed0f7b2d56cd8a80ad428c061d775468ecec2b0be8ea489fb1c5b65ce5441a4b"); CSR = bytes.fromhex("3081d3307b02010030193117301506035504030c0e6861746c732d6964656e746974793059301306072a8648ce3d020106082a8648ce3d03010703420004c4a0e5ad21a334bfaabf6e18747fdcbf74b7b6e09ab784f1faf5706d4a01fc664014b7e6f31ac69cf50715e3f114c9924cc4f693d0ff7f49c17227b94335599da000300a06082a8648ce3d0403020348003045022100c229fc1a1fb18bf214386fd584f7f46c18e303c4755e9e3bd0a083e3052a6b0802201df234bb58ee64d898e6426b7af50dd44991584ddc4539c39de1cbe563c93ed7")
EXPORTER = bytes.fromhex("1f721f3b97c2b58a636855398e938402fd63ae0507a678cd3af134019ae5a99b"); SCTX = bytes.fromhex("7c7b486eab8b6d1e2febf0f4e79ed705eddf512ab77e08c8f16ace4027d3c1f532274f7fc9525271bb828d05d33bb8f3")
TIK = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004c4a0e5ad21a334bfaabf6e18747fdcbf74b7b6e09ab784f1faf5706d4a01fc664014b7e6f31ac69cf50715e3f114c9924cc4f693d0ff7f49c17227b94335599d")
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
def snp_ext(user_data, buflen=32768, probe_size=False):
    """SNP_GET_EXT_REPORT: the report AND the host certificate table. On a VLEK-signed platform
    the leaf lives only here -- AMD does not publish it by CHIP_ID -- so without this a verifier
    has nothing to check the signature against."""
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
certs=b""; notes=[]
try:
    enrol_rep, certs = snp_ext(RD)
    notes.append("ext direct ok len=%d"%len(certs))
except Exception as e:
    notes.append("ext direct failed: %r"%(e,))
    try:                                        # the kernel reports the size it wants, then we retry
        _, need = snp_ext(RD, probe_size=True)
        notes.append("kernel asked for %d bytes"%need)
        enrol_rep, certs = snp_ext(RD, buflen=max(need,4096))
        notes.append("ext two-step ok len=%d"%len(certs))
    except Exception as e2:
        notes.append("ext two-step failed: %r"%(e2,))
        enrol_rep = snp(RD)
try: notes.append("kernel "+open("/proc/version").read().split()[2])
except Exception: pass
out = {"instance": IID, "az": AZ,
       "enrol": base64.b64encode(enrol_rep).decode(),
       "certs": certs.hex(), "notes": notes,
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
