"""The TDX anchor rule, on the reports shipped in evidence/ (offline)."""
import os, glob, json, hashlib
import pytest
from hatls.tee import parse_tdreport, parse_tdx_quote, tdx_anchor

EV = os.path.join(os.path.dirname(__file__), "..", "evidence")
R = os.path.join(EV, "tdx-rtmr-20260922T160500Z")

def _rep(name): return open(os.path.join(R, name), "rb").read()

def test_two_tds_from_one_image_have_no_instance_before_extending():
    a, b = parse_tdreport(_rep("tdx-a-before.tdreport")), parse_tdreport(_rep("tdx-b-before.tdreport"))
    assert a["mrtd"] == b["mrtd"] and a["rtmr3"] == b["rtmr3"] == bytes(48)
    assert tdx_anchor(a) is None and tdx_anchor(b) is None        # fail closed

def test_after_one_extension_each_td_has_a_distinct_instance():
    a, b = parse_tdreport(_rep("tdx-a-after.tdreport")), parse_tdreport(_rep("tdx-b-after.tdreport"))
    assert a["mrtd"] == b["mrtd"]                                  # same image
    ia, ib = tdx_anchor(a), tdx_anchor(b)
    assert ia and ib and ia["instance"] != ib["instance"] and ia["place"] is None

def test_the_module_folded_the_nonce_in():
    """RTMR3' = SHA-384(RTMR3 || data): what TDG.MR.RTMR.EXTEND does, checked on both guests."""
    for t in ("a", "b"):
        d = json.load(open(os.path.join(R, f"tdx-{t}.json")))
        before, after = parse_tdreport(_rep(f"tdx-{t}-before.tdreport")), parse_tdreport(_rep(f"tdx-{t}-after.tdreport"))
        assert hashlib.sha384(before["rtmr3"] + bytes.fromhex(d["nonce"])).digest() == after["rtmr3"]

def test_the_other_registers_did_not_move():
    for t in ("a", "b"):
        before, after = parse_tdreport(_rep(f"tdx-{t}-before.tdreport")), parse_tdreport(_rep(f"tdx-{t}-after.tdreport"))
        for k in ("mrtd", "mrconfigid", "mrowner", "mrownerconfig", "rtmr0", "rtmr1", "rtmr2"):
            assert before[k] == after[k], k

def test_the_earlier_quotes_never_extended_and_so_have_no_instance():
    quotes = sorted(glob.glob(os.path.join(EV, "tdx-quotes-*", "*.bin")))
    assert len(quotes) == 3
    for q in quotes:
        f = parse_tdx_quote(open(q, "rb").read())
        assert f["rtmr3"] == bytes(48) and tdx_anchor(f) is None

def test_both_layouts_read_the_registers_where_a_normal_boot_leaves_them():
    """A normal boot extends RTMR0..2 (firmware, loader, OS) and leaves RTMR3 untouched; MRTD is
    never zero. True through both the TDREPORT and the quote-body offsets, which is the check
    that the two tables point at the same registers. (Written after the first version of the
    quote table put MRTD at +48; this caught it.)"""
    reports = [parse_tdreport(_rep(f"tdx-{t}-before.tdreport")) for t in ("a", "b")]
    reports += [parse_tdx_quote(open(q, "rb").read()) for q in sorted(glob.glob(os.path.join(EV, "tdx-quotes-*", "*.bin")))]
    assert len(reports) == 5
    for f in reports:
        assert f["mrtd"] != bytes(48)
        for k in ("rtmr0", "rtmr1", "rtmr2"): assert f[k] != bytes(48), (f["kind"], k)
        assert f["rtmr3"] == bytes(48), f["kind"]
        assert len(f["report_data"]) == 64
    # the same image family on both dates: identical MRTD across the two TDREPORTs
    assert reports[0]["mrtd"] == reports[1]["mrtd"]
