#!/bin/bash
exec > /var/log/tdx.log 2>&1
set -x
python3 - <<'PY' > /dev/console 2>>/var/log/tdx.log
import os, fcntl, ctypes, hashlib, json, socket
# struct tdx_report_req { __u8 reportdata[64]; __u8 tdreport[1024]; };
# #define TDX_CMD_GET_REPORT0 _IOWR('T', 1, struct tdx_report_req)  -> size 1088
class Req(ctypes.Structure):
    _fields_ = [("reportdata", ctypes.c_ubyte * 64), ("tdreport", ctypes.c_ubyte * 1024)]
IOC = 0xC4405401
notes = []
rep = b""
try:
    rd = hashlib.sha512(b"hatls-tdx-claims").digest()[:64]
    req = Req(); ctypes.memmove(req.reportdata, rd, 64)
    fd = os.open("/dev/tdx_guest", os.O_RDWR)
    try: fcntl.ioctl(fd, IOC, req)
    finally: os.close(fd)
    rep = bytes(req.tdreport)
    notes.append("tdreport %d bytes" % len(rep))
except Exception as e:
    notes.append("tdreport failed: %r" % (e,))
try: notes.append("kernel " + open("/proc/version").read().split()[2])
except Exception: pass
try: notes.append("tdx_guest present: %s" % os.path.exists("/dev/tdx_guest"))
except Exception: pass
out = {"host": socket.gethostname(), "tdreport": rep.hex(), "notes": notes}
payload = json.dumps(out, sort_keys=True).encode(); hx = payload.hex(); CH = 256
print("HATLSMETA %s tdx %d %s" % (out["host"], (len(hx)+CH-1)//CH, hashlib.sha256(payload).hexdigest()))
# Print the payload twice. The serial console interleaves its own lines, and a chunk damaged in
# one pass is simply taken from the other: the reader keys chunks by index, so gaps fill in.
for _pass in range(2):
    for i in range(0, len(hx), CH):
        c = hx[i:i+CH]
        print("HATLSC %04d %s" % (i//CH, c.ljust(CH, "0") if i+CH > len(hx) else c))
print("HATLSLEN %d" % len(hx))
print("HATLSEND")
PY
