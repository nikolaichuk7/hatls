#!/usr/bin/env python3
"""TEE backends for HATLS. MockTEE for local debugging; SevSnpTEE for real hardware.

Both expose the same contract:
    tee.report(report_data: bytes[64]) -> evidence (dict)
    verify(evidence, expected_report_data) -> (ok: bool, chip_id: bytes|None)
"""
import hashlib, os, json, base64, subprocess
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

# ---------- MockTEE: an ephemeral P-384 key stands in for the AMD SP ------------------
class MockTEE:
    def __init__(self, chip_id: bytes):
        self.chip = chip_id
        self.k = ec.generate_private_key(ec.SECP384R1())
        self.pub = self.k.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def report(self, report_data: bytes):
        body = self.chip + report_data
        sig = self.k.sign(body, ec.ECDSA(hashes.SHA384()))
        return {"kind": "mock", "chip": self.chip.hex(), "report_data": report_data.hex(),
                "pub": self.pub.hex(), "sig": sig.hex()}

def mock_verifier(trusted_pubs):
    """trusted_pubs: set of DER SPKI hex allowed to sign. Models the vendor-root trust."""
    def verify(ev, expected_rd):
        if ev.get("kind") != "mock": return False, None
        if ev["pub"] not in trusted_pubs: return False, None
        if bytes.fromhex(ev["report_data"]) != expected_rd: return False, None
        pub = serialization.load_der_public_key(bytes.fromhex(ev["pub"]))
        chip = bytes.fromhex(ev["chip"])
        try:
            pub.verify(bytes.fromhex(ev["sig"]), chip + bytes.fromhex(ev["report_data"]),
                       ec.ECDSA(hashes.SHA384()))
            return True, chip
        except Exception:
            return False, None
    return verify

# ---------- SevSnpTEE: real /dev/sev-guest via a helper on the guest ------------------
class SevSnpTEE:
    """On a real SEV-SNP guest. `report()` shells out to the guest probe that requests a
    VCEK-signed report with the given REPORT_DATA. Verification pulls the VCEK from AMD KDS."""
    def __init__(self, probe="./snp_report"):
        self.probe = probe
    def report(self, report_data: bytes):
        out = subprocess.check_output([self.probe, report_data.hex()])
        raw = bytes.fromhex(out.decode().strip())
        return {"kind": "sev-snp", "report": base64.b64encode(raw).decode(),
                "report_data": report_data.hex()}

def sevsnp_verifier():
    """Verify a real 1184-byte report: parse CHIP_ID/TCB, fetch VCEK from KDS, check P-384 sig,
    check REPORT_DATA. Reuses the logic proven in ietf/analysis/snp_verify_sigs.py."""
    import urllib.request, os, hashlib, time
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import utils
    cache_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)),"vcek-cache"); os.makedirs(cache_dir,exist_ok=True)
    def fetch_vcek(chip,t):
        key=hashlib.sha256(chip+bytes(t)).hexdigest()[:32]; fp=os.path.join(cache_dir,key+".der")
        if os.path.exists(fp): return open(fp,"rb").read()
        url=(f"https://kdsintf.amd.com/vcek/v1/Milan/{chip.hex()}"
             f"?blSPL={t[0]}&teeSPL={t[1]}&snpSPL={t[6]}&ucodeSPL={t[7]}")
        for attempt in range(6):
            try:
                der=urllib.request.urlopen(url,timeout=60).read(); open(fp,"wb").write(der); return der
            except urllib.error.HTTPError as e:
                if e.code==429: time.sleep(3+attempt*2); continue
                raise
        raise RuntimeError("KDS 429 after retries")
    def verify(ev, expected_rd):
        if ev.get("kind") != "sev-snp": return False, None
        b = base64.b64decode(ev["report"])
        if len(b) != 1184: return False, None
        if b[0x50:0x90] != expected_rd: return False, None
        chip = b[0x1A0:0x1E0]; t = b[0x180:0x188]
        cert = x509.load_der_x509_certificate(fetch_vcek(chip,t))
        r = int.from_bytes(b[0x2A0:0x2A0+72][::-1],"big"); s = int.from_bytes(b[0x2A0+72:0x2A0+144][::-1],"big")
        try:
            cert.public_key().verify(utils.encode_dss_signature(r,s), b[:0x2A0], ec.ECDSA(hashes.SHA384()))
            return True, chip
        except Exception:
            return False, None
    return verify
