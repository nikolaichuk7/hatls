#!/usr/bin/env python3
"""TEE backends for HATLS. MockTEE for local debugging; SevSnpTEE for real hardware.

Both expose the same contract:
    tee.report(report_data: bytes[64]) -> evidence (dict)
    verify(evidence, expected_report_data) -> (ok: bool, anchor: bytes|None)

`anchor` is a dict with two separate claims, because they answer different questions and only one
of them is identity:

    {"instance": bytes, "place": bytes | None}

`instance` answers "is this the same Target Environment?" On SEV-SNP that is REPORT_ID, which the
AMD-SP generates per guest and which persists for that guest's lifetime (Firmware ABI 1.54: "The
firmware generates a report ID for each guest that persists with the guest instance throughout its
lifetime"). It is not an input to SNP_LAUNCH_START, so the hypervisor cannot choose it.

`place` answers "which silicon?" That is CHIP_ID, and it is a weaker and different claim: two
guests on one socket share it, and a shared-tenancy VLEK-signed report zeroes it. Measured on our
own archive: six distinct AWS instances report an all-zero CHIP_ID -- and MASK_CHIP_KEY is clear in
all of them -- while their REPORT_IDs are all distinct. Anchoring identity on CHIP_ID is therefore
blind on that platform; anchoring on REPORT_ID is not.

A missing `instance` fails closed. A missing `place` is normal and only matters to a deployment
that asks for it (`Mandate(require_place=True)`).
"""
def _present(v):
    """None for an absent/masked identifier, otherwise the identifier itself."""
    return None if (v is None or not any(v)) else v
import hashlib, os, json, base64, subprocess
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

# ---------- MockTEE: an ephemeral P-384 key stands in for the AMD SP ------------------
class MockTEE:
    """A stand-in for one guest on one chip.

    `instance` models REPORT_ID and defaults to a fresh random value, so two MockTEEs sharing a
    `chip_id` are two guests on one socket -- the case a chip-anchored design cannot see."""
    def __init__(self, chip_id: bytes, instance_id: bytes = None):
        self.chip = chip_id
        self.instance = instance_id if instance_id is not None else os.urandom(32)
        self.k = ec.generate_private_key(ec.SECP384R1())
        self.pub = self.k.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def report(self, report_data: bytes):
        body = self.instance + self.chip + report_data
        sig = self.k.sign(body, ec.ECDSA(hashes.SHA384()))
        return {"kind": "mock", "instance": self.instance.hex(), "chip": self.chip.hex(),
                "report_data": report_data.hex(), "pub": self.pub.hex(), "sig": sig.hex()}

def mock_verifier(trusted_pubs):
    """trusted_pubs: set of DER SPKI hex allowed to sign. Models the vendor-root trust."""
    def verify(ev, expected_rd):
        if ev.get("kind") != "mock": return False, None
        if ev["pub"] not in trusted_pubs: return False, None
        if bytes.fromhex(ev["report_data"]) != expected_rd: return False, None
        pub = serialization.load_der_public_key(bytes.fromhex(ev["pub"]))
        chip = bytes.fromhex(ev["chip"]); inst = bytes.fromhex(ev["instance"])
        try:
            pub.verify(bytes.fromhex(ev["sig"]), inst + chip + bytes.fromhex(ev["report_data"]),
                       ec.ECDSA(hashes.SHA384()))
        except Exception:
            return False, None
        if _present(inst) is None: return True, None          # no instance claim: fail closed
        return True, {"instance": inst, "place": _present(chip)}
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

# ---- SEV-SNP ATTESTATION_REPORT, ABI Table 21 ----
_OFF = {"version":0x00, "policy":0x08, "flags":0x48, "report_data":0x50, "measurement":0x90,
        "host_data":0xC0, "report_id":0x140, "reported_tcb":0x180, "chip_id":0x1A0, "sig":0x2A0}
POLICY_DEBUG = 1 << 19          # host may inspect guest memory: any key inside is unprotected

def parse_snp(b):
    """Field view of a 1184-byte report. Offsets and the signing-key encoding are the ones our
    geoAR verifier corpus was measured with (103 reports, 3 clouds)."""
    import struct
    if len(b) != 1184: raise ValueError(f"not a 1184-byte report: {len(b)}")
    flags = struct.unpack_from("<I", b, _OFF["flags"])[0]
    tcb   = struct.unpack_from("<Q", b, _OFF["reported_tcb"])[0]
    ver   = struct.unpack_from("<I", b, _OFF["version"])[0]
    chip  = b[_OFF["chip_id"]:_OFF["chip_id"]+64]
    if ver < 3: product = "Milan"
    else:
        fam, mod = b[0x188], b[0x189]
        product = ("Milan" if fam == 0x19 and mod <= 0x0f else
                   "Genoa" if fam == 0x19 and 0x10 <= mod <= 0x1f else
                   "Turin" if fam == 0x1a else "Milan")
    return {"version": ver, "product": product,
            "signing_key": {0:"VCEK", 1:"VLEK", 7:"none"}.get((flags >> 2) & 7, (flags >> 2) & 7),
            "mask_chip_key": (flags >> 1) & 1,
            "policy": struct.unpack_from("<Q", b, _OFF["policy"])[0],
            "chip_id": chip, "chip_id_zero": chip == bytes(64),
            "measurement": b[_OFF["measurement"]:_OFF["measurement"]+48],
            "host_data": b[_OFF["host_data"]:_OFF["host_data"]+32],
            "report_id": b[_OFF["report_id"]:_OFF["report_id"]+32],
            "report_data": b[_OFF["report_data"]:_OFF["report_data"]+64],
            "tcb": (tcb & 0xff, (tcb >> 8) & 0xff, (tcb >> 48) & 0xff, (tcb >> 56) & 0xff)}

# ---- Intel TDX: the anchor rule, on the report body ---------------------------------------
# A TDREPORT (1024 B, what the TD gets locally) and a Quote v4 (what a remote party gets) carry
# the same measurement registers at different offsets. Nothing in either is an instance identity
# by construction: two TDs from one image are identical except MROWNER, which the host supplies
# (docs/INSTANCE-IDENTITY.md). A TD can MAKE one: extend RTMR3 once at boot with 48 random bytes
# and discard them. The TDX module folds them in (RTMR3' = SHA-384(RTMR3 || data)); the host has
# no write path to an RTMR; every later report carries the value. Measured on two GCP TDs in
# evidence/tdx-rtmr-20260922T160500Z. The rule mirrors snp_anchor: a zero RTMR3 -- a TD that never
# extended -- is no instance at all, and the mandate fails closed on it.
#
# NOT implemented here: verification of the quote's QE signature and PCK chain against Intel's
# PCS. This reads the body; a deployment must verify the quote first, exactly as sevsnp_verifier
# verifies the SNP report before snp_anchor reads it.
_TDREPORT = {"mrtd": 528, "mrconfigid": 576, "mrowner": 624, "mrownerconfig": 672,
             "rtmr0": 720, "rtmr1": 768, "rtmr2": 816, "rtmr3": 864, "report_data": 128}
# TD report body (Intel Quote v4, 584 B): tee_tcb_svn 0, mr_seam 16, mrsigner_seam 64,
# seam_attributes 112, td_attributes 120, xfam 128, then the registers below, report_data 520.
_QUOTE_BODY = {"mrtd": 136, "mrconfigid": 184, "mrowner": 232, "mrownerconfig": 280,
               "rtmr0": 328, "rtmr1": 376, "rtmr2": 424, "rtmr3": 472, "report_data": 520}

def parse_tdreport(b):
    """Field view of the 1024-byte TDREPORT a TD obtains from its own TDX module."""
    if len(b) != 1024: raise ValueError(f"not a 1024-byte TDREPORT: {len(b)}")
    f = {k: b[o:o+48] for k, o in _TDREPORT.items() if k != "report_data"}
    f["report_data"] = b[128:192]; f["mac"] = b[224:256]; f["kind"] = "tdreport"
    return f

def parse_tdx_quote(q):
    """Field view of the TD report body inside a Quote v4 (48-byte header + 584-byte body)."""
    if len(q) < 632 or int.from_bytes(q[0:2], "little") != 4:
        raise ValueError("not a Quote v4")
    body = q[48:632]
    f = {k: body[o:o+48] for k, o in _QUOTE_BODY.items() if k != "report_data"}
    f["report_data"] = body[520:584]; f["kind"] = "tdx-quote"
    return f

def tdx_anchor(f):
    """The instance claim of a TD, or None. There is no place claim on TDX: nothing in the
    report names the socket, and MROWNER is the host's word, not the chip's."""
    r = f["rtmr3"]
    if r == bytes(48): return None                       # never extended: no instance, fail closed
    return {"instance": r, "place": None}

def snp_anchor(f):
    """{"instance": REPORT_ID, "place": CHIP_ID or None}, or None if there is no instance claim.

    `place` uses two independent signals, because they do not agree in practice: the firmware can
    set MASK_CHIP_KEY, and a platform can simply zero the field. Measured on our archive: 15 AWS
    shared-tenancy VLEK reports carry an all-zero CHIP_ID with MASK_CHIP_KEY *clear* -- the
    identifier is hidden without the flag that says so, so trusting the flag alone would hand back
    64 zero bytes as if they were an identity. Those same reports carry perfectly good REPORT_IDs,
    which is why identity lives there and not here."""
    inst = _present(f["report_id"])
    if inst is None: return None
    place = None if (f["mask_chip_key"] or f["chip_id_zero"]) else f["chip_id"]
    return {"instance": inst, "place": place}

def sevsnp_verifier(require_chain=True, allow_debug=False, measurement=None, ark_sha256=None):
    """Verify a real 1184-byte report and appraise the platform it came from.

      * signature over the report body by the leaf key: the VCEK AMD issued for this CHIP_ID and
        TCB, or, for a VLEK-signed report, the certificate the evidence carries in `leaf_pem`,
        since AMD does not publish that one by CHIP_ID;
      * that leaf chains to the AMD root: VCEK -> ASK -> ARK, ARK self-signed (require_chain);
      * the guest POLICY does not permit DEBUG, which would let the host read the key (allow_debug);
      * the launch MEASUREMENT equals a pinned value, when one is given;
      * REPORT_DATA binds exactly the link we were asked about.

    Returns (ok, anchor). `anchor` is None on a platform that exposes no instance identifier; the
    caller decides whether that is acceptable -- Mandate(require_anchor=True) refuses it.
    """
    import urllib.request, urllib.error, os, hashlib, time
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import utils, rsa
    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vcek-cache")
    os.makedirs(cache_dir, exist_ok=True)

    def _get(url, cache_key):
        fp = os.path.join(cache_dir, cache_key)
        if os.path.exists(fp): return open(fp, "rb").read()
        for attempt in range(6):
            try:
                d = urllib.request.urlopen(url, timeout=60).read(); open(fp, "wb").write(d); return d
            except urllib.error.HTTPError as e:
                if e.code == 429: time.sleep(3 + attempt * 2); continue
                raise
        raise RuntimeError(f"KDS rate-limited after retries: {url}")

    def leaf_cert(f, supplied_pem=None):
        """The certificate that signed this report. Returns (parsed, der).

        For a VCEK report AMD publishes the leaf by CHIP_ID and we fetch it. For a VLEK report it
        does not -- the key is issued to the cloud provider, not to a chip -- so the leaf has to
        come from the host certificate table the guest reads alongside the report. Refusing VLEK
        outright, as this verifier first did, refuses AWS shared tenancy entirely: the anchor is
        there and perfectly usable, but nothing can appraise the evidence carrying it."""
        if f["signing_key"] == "VLEK":
            if supplied_pem is None:
                raise ValueError("VLEK-signed report and no leaf certificate supplied: AMD KDS "
                                 "does not publish it by CHIP_ID, so the guest must pass the one "
                                 "from its host certificate table")
            der = x509.load_pem_x509_certificate(supplied_pem).public_bytes(
                serialization.Encoding.DER)
            return x509.load_der_x509_certificate(der), der
        if f["signing_key"] != "VCEK":
            raise ValueError(f"{f['signing_key']}-signed report: unsupported signing key")
        t = f["tcb"]
        url = (f"https://kdsintf.amd.com/vcek/v1/{f['product']}/{f['chip_id'].hex()}"
               f"?blSPL={t[0]}&teeSPL={t[1]}&snpSPL={t[2]}&ucodeSPL={t[3]}")
        der = _get(url, hashlib.sha256(url.encode()).hexdigest()[:32] + ".der")
        return x509.load_der_x509_certificate(der), der

    def chain_ok(leaf_der, f):
        """Path validation leaf -> intermediate -> ARK with ARK as the only trust anchor.

        Done through OpenSSL on purpose. AMD signs ASK and ARK with RSASSA-PSS and encodes
        trailerField=1 explicitly, which is the DEFAULT -- X.690 11.5 forbids that in DER, so
        strict parsers refuse to load the chain at all (python-cryptography did so through 42.x;
        43.0 and later tolerate it -- see docs/AMD-CERT-DER.md). A
        verifier that treats "cannot parse the root" as "skip the root" silently drops back to
        trusting whatever key signed the report. Measured 21 Sep 2026 on the live KDS endpoint.
        """
        import re
        from OpenSSL import crypto as oc
        kind = "vlek" if f["signing_key"] == "VLEK" else "vcek"
        pem = _get(f"https://kdsintf.amd.com/{kind}/v1/{f['product']}/cert_chain",
                   f"{f['product']}-{kind}-chain.pem")
        blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
        if len(blocks) < 2: return False, "AMD chain did not contain the intermediate and ARK"
        certs = [oc.load_certificate(oc.FILETYPE_PEM, b) for b in blocks]
        ask, ark = certs[0], certs[-1]
        if ark_sha256 and hashlib.sha256(
                oc.dump_certificate(oc.FILETYPE_ASN1, ark)).hexdigest() != ark_sha256:
            return False, "AMD root key does not match the pinned value"
        store = oc.X509Store(); store.add_cert(ark)          # ARK alone is the trust anchor
        try:
            oc.X509StoreContext(store, oc.load_certificate(oc.FILETYPE_ASN1, leaf_der),
                                chain=[ask]).verify_certificate()
            return True, "chain ok"
        except Exception as e:
            return False, f"certificate chain broken: {e}"

    def verify(ev, expected_rd):
        if ev.get("kind") != "sev-snp": return False, None
        try:
            b = base64.b64decode(ev["report"]); f = parse_snp(b)
        except Exception:
            return False, None
        if f["report_data"] != expected_rd: return False, None
        if (f["policy"] & POLICY_DEBUG) and not allow_debug:
            return False, None          # DEBUG-capable guest: the host can read the key
        if measurement is not None and f["measurement"] != measurement:
            return False, None
        try:
            supplied = ev.get("leaf_pem")
            cert, cert_der = leaf_cert(f, supplied.encode() if supplied else None)
            r = int.from_bytes(b[_OFF["sig"]:_OFF["sig"]+48], "little")
            s = int.from_bytes(b[_OFF["sig"]+72:_OFF["sig"]+120], "little")
            cert.public_key().verify(utils.encode_dss_signature(r, s), b[:_OFF["sig"]],
                                     ec.ECDSA(hashes.SHA384()))
            if require_chain:
                ok, _why = chain_ok(cert_der, f)
                if not ok: return False, None
        except Exception:
            return False, None
        return True, snp_anchor(f)
    return verify
