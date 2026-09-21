#!/bin/bash
exec > /var/log/hatls.log 2>&1
set -x
python3 - <<'PY' > /dev/console 2>>/var/log/hatls.log
import os, fcntl, ctypes, hashlib, hmac, base64, json, socket
NONCE=bytes.fromhex("c01ef1a44efaf86d07bdd4de97a40222c43f6e1e9dcd394350091d637dbb70c5"); CSR=bytes.fromhex("3081d3307b02010030193117301506035504030c0e6861746c732d6964656e746974793059301306072a8648ce3d020106082a8648ce3d03010703420004edfed4dfb92bb9c8bfade7d67ec70c20ec1a51a846fbea3b1e6d1f562a539046789b5a3fde9e9d958e8c8619fb8de68466195062b38121a30dfa0c4bf329f43ca000300a06082a8648ce3d04030203480030450220558a3786c1df6c102dec2fc952813ebc94aa92605d95eeeff6af79442f946f67022100f06e8e43f089d74c746e8da1d93bffc5f3537761976bbfd350c281debd1bdcb6")
EXPORTER=bytes.fromhex("ca2c542b06b88d8f3f1df9066b4eebedcd753631a8d51ccc5367f5a5e9a7bbb3"); SCTX=bytes.fromhex("245e9b7aa09bf5d9d2306fe7751fabdc563248cce87e6b5a6926cf7536c4e7512b1d2128ba806025527132bc7f43a07a"); TIK=bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004edfed4dfb92bb9c8bfade7d67ec70c20ec1a51a846fbea3b1e6d1f562a539046789b5a3fde9e9d958e8c8619fb8de68466195062b38121a30dfa0c4bf329f43c")
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
