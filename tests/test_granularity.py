"""Instance versus place versus class, pinned on the evidence this repository ships (offline).
See examples/granularity.py and docs/INSTANCE-IDENTITY.md."""
import os, sys, glob, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples"))
from malleability import shipped_reports
from granularity import TD, CSP_ID_OID
from hatls.tee import parse_snp, snp_anchor
from cryptography import x509

REPS = shipped_reports()
GCP = [(b, l) for b, (s, l) in REPS.items() if not s.startswith("aws-")]
AWS = [(b, l) for b, (s, l) in REPS.items() if s.startswith("aws-")]

def test_the_archive_has_both_clouds():
    assert len(GCP) >= 60 and len(AWS) >= 12

def test_aws_chip_id_is_always_zero_and_the_flag_never_says_so():
    for b, _ in AWS:
        f = parse_snp(b)
        assert f["signing_key"] == "VLEK"
        assert f["chip_id"] == bytes(64)
        assert f["mask_chip_key"] == 0          # the report's own flag does not announce the masking

def test_gcp_chip_id_is_never_zero():
    for b, _ in GCP:
        f = parse_snp(b); assert f["signing_key"] == "VCEK" and f["chip_id"] != bytes(64)

def test_report_id_is_distinct_per_instance_and_shared_within_one():
    # every AWS instance's enrol and step reports carry one REPORT_ID; different instances differ
    ids = {}
    for p in glob.glob(os.path.join(os.path.dirname(__file__), "..", "evidence", "aws-anchor-*", "probes.json")):
        d = json.load(open(p))
        for iid, e in d.items():
            import base64
            blobs = []
            for k in ("enrol", "step"):
                if isinstance(e.get(k), str):
                    try: b = base64.b64decode(e[k])
                    except Exception: continue                  # the damaged first run; see its README
                    if len(b) == 1184: blobs.append(b)
            if not blobs: continue
            rids = {parse_snp(b)["report_id"] for b in blobs}
            assert len(rids) == 1, (p, iid)
            ids.setdefault(iid, set()).update(rids)
    seen = [next(iter(v)) for v in ids.values()]
    assert len(seen) == len(set(seen)) >= 8

def test_one_chip_serves_several_instances_over_time():
    per_chip = {}
    for b, _ in GCP:
        f = parse_snp(b); per_chip.setdefault(f["chip_id"], set()).add(f["report_id"])
    assert len(per_chip) >= 5
    assert all(len(v) >= 2 for v in per_chip.values())     # chip = place, not instance

def test_what_is_running_does_not_separate_instances():
    for items in (GCP, AWS):
        assert len({b[0x10:0x20] for b, _ in items}) == 1      # FAMILY_ID
        assert len({b[0x20:0x30] for b, _ in items}) == 1      # IMAGE_ID
        assert len({b[0xC0:0xE0] for b, _ in items}) == 1      # HOST_DATA

def test_vlek_is_endorsed_per_region_not_per_instance():
    regions = set()
    for b, leaf in AWS:
        if not leaf: continue
        c = x509.load_der_x509_certificate(bytes.fromhex(leaf))
        ext = [e for e in c.extensions if e.oid.dotted_string == CSP_ID_OID]
        assert ext and b"amazonaws.com" in ext[0].value.value
        regions.add(ext[0].value.value)
    assert len(regions) == 2                                  # two regions in the run, two keys

def test_the_anchor_rule_uses_content_not_the_flag():
    for b, _ in AWS:
        a = snp_anchor(parse_snp(b)); assert a is not None and a["instance"] != bytes(32) and a["place"] is None
    for b, _ in GCP:
        a = snp_anchor(parse_snp(b)); assert a["place"] is not None

def test_tdx_only_mrowner_differs():
    runs = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "evidence", "tdx-claims-*", "probes.json")))
    d = json.load(open(runs[-1])); tds = [bytes.fromhex(v["tdreport"]) for v in d.values() if isinstance(v, dict) and "tdreport" in v]
    a, b = tds[:2]
    differ = {k for k, (o, n) in TD.items() if a[o:o+n] != b[o:o+n]}
    assert differ == {"REPORTMACSTRUCT.teeinfohash", "REPORTMACSTRUCT.mac", "TDINFO.MROWNER"}
