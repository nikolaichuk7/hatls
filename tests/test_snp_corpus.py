"""Parse the real SEV-SNP reports archived in evidence/ -- offline, no network, no cloud.

These are genuine 1184-byte reports from live GCP confidential VMs. They guard the field offsets
and the anchor rule against silent drift, and they are the reason the masked-anchor defect was
found: an all-zero CHIP_ID must never be handed back as an identity.
"""
import os, sys, json, glob, base64, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hatls.tee import parse_snp, snp_anchor, POLICY_DEBUG

ROOT = os.path.join(os.path.dirname(__file__), "..", "evidence")

def _reports():
    out = []
    for p in glob.glob(os.path.join(ROOT, "**", "*.json"), recursive=True):
        try: doc = json.load(open(p))
        except Exception: continue
        for step in (doc.get("chain") or []):
            if "report" in step: out.append((p, base64.b64decode(step["report"])))
        if "report" in doc: out.append((p, base64.b64decode(doc["report"])))
    return out

REPORTS = _reports()

def test_the_archive_is_present():
    assert REPORTS, "no archived hardware reports found under evidence/"

def test_every_archived_report_parses():
    for path, b in REPORTS:
        assert len(b) == 1184, f"{path}: {len(b)} bytes"
        f = parse_snp(b)
        assert f["version"] >= 2 and f["product"] in ("Milan", "Genoa", "Turin")
        assert f["signing_key"] in ("VCEK", "VLEK", "none")

def test_no_archived_guest_allowed_debug():
    """A DEBUG-capable guest lets the host read its memory, so its key is not protected."""
    for path, b in REPORTS:
        assert not (parse_snp(b)["policy"] & POLICY_DEBUG), f"{path}: DEBUG policy set"

def test_anchor_is_absent_exactly_when_the_identifier_is():
    for path, b in REPORTS:
        f = parse_snp(b)
        assert (snp_anchor(f) is None) == bool(f["mask_chip_key"] or f["chip_id_zero"])

def test_a_zeroed_chip_id_never_becomes_an_identity():
    for path, b in REPORTS:
        f = dict(parse_snp(b)); f["chip_id"] = bytes(64); f["chip_id_zero"] = True
        assert snp_anchor(f) is None
