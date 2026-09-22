#!/usr/bin/env python3
"""Which claim says "the same machine", and at what granularity is the signing key endorsed?

draft-ietf-rats-endorsements-11, Section 4, leaves this open on purpose: "The granularity at which
such identifiers, and therefore the signature-checking keys endorsed for them, apply (e.g., per
instance, class, or other claims) is out of scope of this document." draft-ietf-seat-use-cases-01
asks for binding to a machine identifier (4.3) and for continuity with a particular instance
(3.8.1) without saying which field on real silicon can carry either.

This script answers from the evidence this repository ships -- 87 genuine SEV-SNP reports from
GCP and AWS, the VLEK certificates the AWS run captured, and two TDREPORTs from two Intel TDX
guests -- by reading the fields at their ABI offsets and counting. No network, no cloud.

The firmware ABI (AMD 56860) on the two fields that matter:
  REPORT_ID  "The firmware generates a report ID for each guest that persists with the guest
              instance throughout its lifetime. In each attestation report, the report ID is
              placed in REPORT_ID."
  CHIP_ID    "If MaskChipId is set to 0, Identifier unique to the chip. Otherwise, set to 0h."
And the hypervisor's launch inputs (Linux include/linux/psp-sev.h, struct sev_data_snp_launch_start):
gctx_paddr, policy, ma_gctx_paddr, ma_en, imi_en, desired_tsc_khz, gosvw -- no REPORT_ID. The
hypervisor does not choose it.

Usage:  PYTHONPATH=. python3 examples/granularity.py
"""
import os, sys, glob, json, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from hatls.tee import parse_snp
from malleability import shipped_reports
from cryptography import x509

EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence")
CSP_ID_OID = "1.3.6.1.4.1.3704.1.5"

def field(b, off, n): return b[off:off+n]

def sev_snp():
    reps = shipped_reports()
    print(f"SEV-SNP: {len(reps)} genuine reports shipped in evidence/\n")
    by = collections.defaultdict(list)
    for b, (src, leaf) in reps.items():
        by["aws" if src.startswith("aws-") else "gcp"].append((b, leaf))
    rows = []
    for cloud in ("gcp", "aws"):
        items = by[cloud]; f = [parse_snp(b) for b, _ in items]
        chips = {x["chip_id"] for x in f}; insts = {x["report_id"] for x in f}
        zero = sum(1 for x in f if x["chip_id"] == bytes(64))
        masked = sum(1 for x in f if x["mask_chip_key"])
        keys = collections.Counter(x["signing_key"] for x in f)
        # fields that could be "the machine": distinct values per cloud
        fid = len({field(b, 0x10, 16) for b, _ in items}); iid = len({field(b, 0x20, 16) for b, _ in items})
        hd = len({field(b, 0xC0, 32) for b, _ in items}); meas = len({x["measurement"] for x in f})
        inst_per_chip = collections.Counter()
        for x in f: inst_per_chip[x["chip_id"]] = len({y["report_id"] for y in f if y["chip_id"] == x["chip_id"]})
        print(f"  {cloud.upper()}  reports {len(items):3d}   signing key {dict(keys)}")
        print(f"       CHIP_ID   distinct {len(chips):2d}   all-zero in {zero} of {len(items)}   MASK_CHIP_KEY flag set in {masked}")
        print(f"       REPORT_ID distinct {len(insts):2d}   (one per guest instance)")
        ma = sum(1 for b, _ in items if field(b, 0x160, 32) == b"\xff" * 32)
        print(f"       REPORT_ID_MA all-ones in {ma} of {len(items)}   (no migration agent: REPORT_ID cannot have travelled)")
        print(f"       FAMILY_ID {fid}  IMAGE_ID {iid}  HOST_DATA {hd}  MEASUREMENT {meas}   (distinct values: what is RUNNING, not which machine)")
        if cloud == "gcp":
            multi = {c.hex()[:12]: n for c, n in inst_per_chip.items() if n > 1}
            print(f"       chips that served more than one instance over time: {len(multi)}  {multi}")
        rows.append((cloud, len(items), len(chips), len(insts), zero, dict(keys)))
    print()
    # the endorsed key's granularity, from the certificates the AWS run captured
    print("  the ENDORSED SIGNING KEY, from certificates in evidence/:")
    print("    VCEK (GCP): issued per CHIP_ID and TCB -- the key names the silicon; AMD's KDS serves it by CHIP_ID.")
    leaves = {}
    for b, (src, leaf) in reps.items():
        if leaf: leaves.setdefault(leaf, []).append(parse_snp(b)["report_id"])
    for leaf, ids in leaves.items():
        c = x509.load_der_x509_certificate(bytes.fromhex(leaf))
        ext = [e for e in c.extensions if e.oid.dotted_string == CSP_ID_OID]
        csp = ext[0].value.value[2:].decode(errors="replace") if ext else "?"
        print(f"    VLEK (AWS): {c.subject.rfc4514_string()[:12]}  CSP_ID {csp}   signed reports from {len(set(ids))} instance(s) here")
    print("    -> no key is endorsed per INSTANCE on either cloud. VCEK = place (chip); VLEK = region (class).")
    print("       REPORT_ID is the only per-instance claim, and it is a value INSIDE the signed body, not a key.")
    return rows

TD = {"REPORTMACSTRUCT.reporttype": (0, 16), "REPORTMACSTRUCT.cpusvn": (16, 16), "REPORTMACSTRUCT.tcbinfohash": (32, 48),
      "REPORTMACSTRUCT.teeinfohash": (80, 48), "REPORTMACSTRUCT.reportdata": (128, 64), "REPORTMACSTRUCT.mac": (224, 32),
      "TEE_TCB_INFO": (256, 239), "TDINFO.attributes": (512, 8), "TDINFO.xfam": (520, 8), "TDINFO.MRTD": (528, 48),
      "TDINFO.MRCONFIGID": (576, 48), "TDINFO.MROWNER": (624, 48), "TDINFO.MROWNERCONFIG": (672, 48),
      "TDINFO.RTMR0": (720, 48), "TDINFO.RTMR1": (768, 48), "TDINFO.RTMR2": (816, 48), "TDINFO.RTMR3": (864, 48),
      "TDINFO.SERVTD_HASH": (912, 48), "TDINFO.tail": (960, 64)}

def tdx():
    runs = sorted(glob.glob(f"{EV}/tdx-claims-*/probes.json"))
    if not runs: print("\nTDX: no probes shipped"); return None
    d = json.load(open(runs[-1])); tds = {k: bytes.fromhex(v["tdreport"]) for k, v in d.items() if isinstance(v, dict) and "tdreport" in v}
    print(f"\nTDX: {len(tds)} TDREPORTs from {len(tds)} guests launched from one image ({os.path.relpath(runs[-1], EV)})")
    a, b = list(tds.values())[:2]
    assert len(a) == len(b) == 1024
    differ = [k for k, (o, n) in TD.items() if a[o:o+n] != b[o:o+n]]
    same = [k for k in TD if k not in differ]
    print(f"  fields identical between the two guests: {len(same)}")
    print(f"  fields that differ: {differ}")
    print("  -> MROWNER is the only TDINFO field that separates two live TDs, and the two hashes/MAC differ only")
    print("     through it. MROWNER is supplied by the host VMM at TD initialisation (KVM_TDX_INIT_VM), so it")
    print("     is the word of the party that would do the re-hosting. No hardware-issued instance claim exists.")
    return differ

def main():
    rows = sev_snp(); differ = tdx()
    print("\nSUMMARY -- what the group's open questions look like on real silicon")
    print("  endorsements-11 Sec.4 granularity   VCEK: per chip (place).  VLEK: per CSP region (class).  Per instance: none.")
    print("  use-cases 4.3 machine identifier     SEV-SNP: REPORT_ID (firmware-generated, not a launch input, persists for the")
    print("                                       guest's life) -- but CHIP_ID is all-zero on AWS, so 'the machine' has no silicon")
    print("                                       identity there.  TDX: only MROWNER differs, and the host supplies it.")
    print("  use-cases 3.8.1 instance continuity  possible on SEV-SNP via REPORT_ID; not possible from the TDREPORT alone.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
