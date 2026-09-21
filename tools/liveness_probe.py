#!/usr/bin/env python3
"""Liveness beacon probe — runs inside a real SEV-SNP guest.

Measures the minimal Delta-t: how fast the guest can emit a fresh hardware liveness beacon
(a SEV-SNP report over a monotonically advancing counter). This sets the lower bound on the
residual attack window against a physical-insider (layer 6): any exploitation longer than the
beacon interval leaves a trace (a counter conflict if parallel, a gap if it seizes the chip).

It also reads the vTPM clock/resetCount/restartCount as the hardware monotonic anchor that a
mandate uses to reject rollback of its own view."""
import os, fcntl, ctypes, hashlib, time, json, subprocess

class Req(ctypes.Structure):  _fields_=[("user_data",ctypes.c_ubyte*64),("vmpl",ctypes.c_uint32),("flags",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24)]
class Resp(ctypes.Structure): _fields_=[("status",ctypes.c_uint32),("report_size",ctypes.c_uint32),("rsvd",ctypes.c_ubyte*24),("report",ctypes.c_ubyte*4000)]
class Io(ctypes.Structure):   _fields_=[("msg_version",ctypes.c_ubyte),("req_data",ctypes.c_uint64),("resp_data",ctypes.c_uint64),("exitinfo2",ctypes.c_uint64)]
def snp_report(user_data):
    req=Req(); ctypes.memmove(req.user_data,user_data,64); resp=Resp()
    io=Io(1,ctypes.addressof(req),ctypes.addressof(resp),0)
    fd=os.open("/dev/sev-guest",os.O_RDWR); fcntl.ioctl(fd,0xC0205300,io); os.close(fd)
    if resp.status!=0: raise RuntimeError(f"fw {resp.status}")
    return bytes(resp.report[:1184])

OUT=f"/root/liveness/{time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())}"; os.makedirs(OUT,exist_ok=True); os.chdir(OUT)
meta=lambda k: os.popen(f'curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/{k}').read()
zone=meta("zone").split("/")[-1]; iid=meta("name")

# 1) beacon cost: emit N reports over an advancing counter, time each
N=64; link=hashlib.sha256(b"liveness-seed").digest(); times=[]; chips=set()
for c in range(N):
    rd=hashlib.sha512(b"HATLS-liveness"+link+c.to_bytes(8,"big")).digest()
    t0=time.perf_counter(); rep=snp_report(rd); dt=(time.perf_counter()-t0)*1000
    times.append(dt); chips.add(rep[0x1A0:0x1E0].hex()[:16]); link=hashlib.sha256(rep).digest()
times.sort()
res={"zone":zone,"instance":iid,"chip":list(chips),"beacons":N,
     "beacon_ms_min":round(times[0],2),"beacon_ms_median":round(times[N//2],2),"beacon_ms_max":round(times[-1],2),
     "beacons_per_sec_median":round(1000/times[N//2],1)}

# 2) vTPM monotonic anchor: clock/resetCount/restartCount from a quote
try:
    subprocess.run("export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq tpm2-tools >/dev/null 2>&1",shell=True)
    subprocess.run("tpm2_startup -c >/dev/null 2>&1 || true",shell=True)
    q=subprocess.run("tpm2_quote -c 0x81010001 -l sha256:0,1 -q deadbeef -m msg.bin -s sig.bin -o pcr.bin 2>/dev/null || tpm2_readclock 2>/dev/null",shell=True,capture_output=True,text=True)
    rc=subprocess.run("tpm2_readclock 2>/dev/null",shell=True,capture_output=True,text=True).stdout
    res["vtpm_readclock"]=rc.strip()[:400]
except Exception as e:
    res["vtpm_error"]=str(e)[:120]

json.dump(res,open("liveness.json","w"))
print(json.dumps(res,indent=2))
