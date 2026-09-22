#!/usr/bin/env python3
"""Hardware attestation reports are signature-malleable. Measured on the reports this repository ships.

The AMD Secure Processor signs a SEV-SNP report with ECDSA P-384. ECDSA has a well-known
property: if (r, s) is a valid signature then so is (r, n - s). A signer can refuse to produce
the second form (low-S canonicalisation, the BIP-62 rule) and a verifier can refuse to accept it;
AMD's firmware does neither, and neither does the standard verifier. So anyone holding one genuine
report can produce a SECOND, byte-different, still-valid report of the same body -- without any
AMD key. Intel's Quoting Enclave behaves the same on TDX quotes (see docs/SIGNATURE-MALLEABILITY.md).

This is not a break of attestation. The body -- REPORT_DATA, MEASUREMENT, REPORT_ID, CHIP_ID,
policy, TCB -- is untouched, so nonces, binders, relay defences and claims are unaffected, and
no key is recovered (the nonce RNG is checked below). What it breaks is any layer that treats the
BYTES of a report, or its signature, as the report's identity: a replay cache keyed by hash, a
transparency log that registers statements over the hash of a payload (draft-ietf-scitt-architecture
allows exactly that), a "seen before" check, a dedup. Those see one piece of evidence as two.

HATLS is immune by construction: the mandate identifies evidence by REPORT_ID and CHIP_ID read
from the body, and its ledger entries are over links, not report bytes. This script is the reason.

Everything below runs on the genuine reports in evidence/ -- no cloud, no new hardware. The flip is
verified with the repository's own sevsnp_verifier, so "the flipped report verifies" means it
passes the full check: signature, VCEK -> ASK -> ARK chain, REPORT_DATA.

Usage:  PYTHONPATH=. python3 examples/malleability.py
"""
import os, sys, re, glob, json, base64, hashlib, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.tee import sevsnp_verifier, parse_snp, _OFF

N384 = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
SIG, BODY = _OFF["sig"], _OFF["sig"]           # signature at 0x2A0; the body is everything before it
EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence")

def rs(rep):
    r = int.from_bytes(rep[SIG:SIG+48], "little"); s = int.from_bytes(rep[SIG+72:SIG+120], "little")
    return r, s

def with_s(rep, s_new):
    """The same report with s replaced, encoded as AMD does: 72-byte little-endian field."""
    return rep[:SIG+72] + s_new.to_bytes(72, "little") + rep[SIG+144:]

def vlek_pem(leaf_hex):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    return x509.load_der_x509_certificate(bytes.fromhex(leaf_hex)).public_bytes(serialization.Encoding.PEM).decode()

def shipped_reports():
    """Every genuine 1184-byte report under evidence/, with the VLEK leaf where the run shipped one."""
    out = {}
    def b64_reports(obj):
        """every base64 string in `obj` that decodes to a 1184-byte report"""
        if isinstance(obj, str) and 1500 <= len(obj) <= 1700:
            try:
                b = base64.b64decode(obj)
                if len(b) == 1184: yield b
            except Exception: pass
        elif isinstance(obj, dict):
            for v in obj.values(): yield from b64_reports(v)
        elif isinstance(obj, list):
            for v in obj: yield from b64_reports(v)
    for p in glob.glob(f"{EV}/**/*.json", recursive=True):
        try: d = json.load(open(p))
        except Exception: continue
        rel = os.path.relpath(p, EV)
        if isinstance(d, dict) and all(isinstance(v, dict) for v in d.values()) and any("leaf" in v for v in d.values()):
            # AWS runs: one entry per instance, each with ITS OWN VLEK leaf (regions differ)
            for e in d.values():
                for b in b64_reports(e): out.setdefault(b, (rel, e.get("leaf")))
        else:
            for b in b64_reports(d): out.setdefault(b, (rel, None))
    for p in glob.glob(f"{EV}/**/*.bin", recursive=True):
        b = open(p, "rb").read()
        if len(b) == 1184: out.setdefault(b, (os.path.relpath(p, EV), None))
    return out

def main():
    reps = shipped_reports()
    print(f"genuine SEV-SNP reports shipped in evidence/: {len(reps)} distinct\n")

    # 1. structural: is s canonical? is the nonce healthy?
    hi = lo = bad = 0; rvals = collections.Counter()
    for b in reps:
        r, s = rs(b); rvals[r] += 1
        if not (0 < r < N384 and 0 < s < N384): bad += 1
        elif s >= N384 // 2: hi += 1
        else: lo += 1
    print("1. THE SIGNER")
    print(f"   s >= n/2 (high-S)                    {hi}")
    print(f"   s <  n/2 (low-S)                     {lo}")
    print(f"   r or s out of range                  {bad}")
    print(f"   -> a low-S canonicalising signer produces 0 high-S; AMD's firmware produces them at the")
    print(f"      rate of an unconstrained signer.")
    dup_r = sum(1 for c in rvals.values() if c > 1)
    print(f"   distinct r values                    {len(rvals)} of {len(reps)}   (repeated r: {dup_r} -- a repeated nonce would leak the key)")
    print(f"   r >= n/2                             {sum(1 for r in rvals if r >= N384//2)} of {len(rvals)}   (uniform expectation ~{len(rvals)//2})")

    # 2. randomised signing: identical bodies, different signatures
    by_body = collections.defaultdict(set)
    for b in reps: by_body[b[:BODY]].add(b[SIG:])
    multi = {k: v for k, v in by_body.items() if len(v) > 1}
    print("\n2. RANDOMISED SIGNING")
    print(f"   bodies that appear more than once    {len(multi)}")
    print(f"   of those, with DIFFERENT signatures  {sum(1 for v in multi.values() if len(v) > 1)}")
    print(f"   -> a deterministic signer (RFC 6979) would sign an identical body identically.")

    # 3. the flip, through the repository's own verifier
    verify = sevsnp_verifier(require_chain=True)
    print("\n3. THE FLIP, VERIFIED WITH hatls.tee.sevsnp_verifier (signature + AMD chain + REPORT_DATA)")
    orig_ok = flip_ok = tried = skipped = 0; forged_example = None
    for b, (src, leaf) in sorted(reps.items(), key=lambda kv: kv[1][0]):
        f = parse_snp(b)
        ev = {"kind": "sev-snp", "report": base64.b64encode(b).decode()}
        if f["signing_key"] == "VLEK":
            if not leaf: skipped += 1; continue                # AMD does not publish VLEK by chip; no leaf shipped
            ev["leaf_pem"] = vlek_pem(leaf)
        tried += 1
        ok, _ = verify(ev, f["report_data"])
        r, s = rs(b); flipped = with_s(b, N384 - s)
        ev2 = dict(ev, report=base64.b64encode(flipped).decode())
        ok2, anchor2 = verify(ev2, f["report_data"])
        orig_ok += ok; flip_ok += ok2
        if ok and ok2 and forged_example is None: forged_example = (src, b, flipped, anchor2)
    print(f"   reports tried                        {tried}   (skipped {skipped} VLEK reports whose run shipped no leaf)")
    print(f"   original verifies                    {orig_ok} of {tried}")
    print(f"   flipped (r, n-s) verifies            {flip_ok} of {tried}")
    if forged_example:
        src, b, fl, anc = forged_example
        print(f"\n   example, {src}:")
        print(f"     original sha256                    {hashlib.sha256(b).hexdigest()[:32]}...")
        print(f"     forged   sha256                    {hashlib.sha256(fl).hexdigest()[:32]}...")
        print(f"     bytes differ                       {b != fl}")
        print(f"     body (0x000..0x2A0) identical      {b[:BODY] == fl[:BODY]}")
        print(f"     verifier's anchor for the forgery  instance {anc['instance'].hex()[:16]}... -- the same instance")
        print(f"     no AMD key was used.")

    # 4. controls: the verifier must reject what is actually wrong, and the usual remedy must be shown
    print("\n4. CONTROLS")
    if forged_example:
        src, b, fl, _ = forged_example
        f = parse_snp(b); ev = {"kind": "sev-snp", "report": base64.b64encode(b).decode()}
        r, s_ = rs(b)
        bad_s   = with_s(b, (N384 - s_ + 1) % N384)                       # not the conjugate: a wrong s
        bad_body = b[:0x50] + bytes([b[0x50] ^ 1]) + b[0x51:]              # one bit of REPORT_DATA
        ok_bad_s, _ = verify({**ev, "report": base64.b64encode(bad_s).decode()}, f["report_data"])
        ok_bad_body, _ = verify({**ev, "report": base64.b64encode(bad_body).decode()}, parse_snp(bad_body)["report_data"])
        print(f"   s replaced by n-s+1 (not a conjugate)  verifies: {ok_bad_s}    (must be False)")
        print(f"   one bit of the body flipped           verifies: {ok_bad_body}    (must be False)")
    print(f"   a verifier that enforced low-S would REJECT {hi} of {len(reps)} GENUINE reports here: the")
    print(f"   remedy that works for Bitcoin is not available against a signer that emits high-S itself.")
    print(f"   The remedy left is to identify evidence by its body.")

    # 5. Intel TDX: the same question on the quotes this repository ships
    print("\n5. INTEL TDX QUOTES  (evidence/tdx-quotes-20260911/, Quote v4, QE ECDSA-P256)")
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    t_hi = t_orig = t_flip = t_n = 0
    for p in sorted(glob.glob(f"{EV}/tdx-quotes-*/*.bin")):
        q = open(p, "rb").read(); hdr, tdrep = 48, 584
        signed = q[:hdr+tdrep]; sd = q[hdr+tdrep+4:]
        sig, xy = sd[:64], sd[64:128]
        r = int.from_bytes(sig[:32], "big"); s_ = int.from_bytes(sig[32:], "big")
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big"), ec.SECP256R1()).public_key()
        def ok(rr, ss):
            try: pub.verify(utils.encode_dss_signature(rr, ss), signed, ec.ECDSA(hashes.SHA256())); return True
            except Exception: return False
        o, fl = ok(r, s_), ok(r, N256 - s_); t_n += 1; t_orig += o; t_flip += fl; t_hi += (s_ >= N256 // 2)
        print(f"   {os.path.basename(p):28s} {'HIGH-S' if s_ >= N256//2 else 'low-S '}   original verifies: {o}   (r, n-s) verifies: {fl}")
    print(f"   quotes {t_n}: high-S {t_hi}, originals verify {t_orig}, flipped verify {t_flip}   (attestation key taken from the quote itself;")
    print(f"   its QE-report/PCK certification is the same for both forms and is not re-verified here)")

    print("\nWHAT THIS MEANS")
    print("   unaffected: nonces, binders, relay/replay defences, claims, keys -- the body is unchanged.")
    print("   affected:   anything that identifies evidence by its bytes or its signature: hash-keyed replay")
    print("               caches, statements over the hash of a payload, dedup, 'already registered'.")
    print("   HATLS:      identity is REPORT_ID/CHIP_ID from the body; ledger entries are over links, not")
    print("               report bytes; a forged copy is the same evidence to the mandate.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
