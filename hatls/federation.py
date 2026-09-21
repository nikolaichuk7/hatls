#!/usr/bin/env python3
"""Two mandates over one identity: what is actually achievable, and how.

Preventing divergence needs consensus -- a single writer or a quorum -- and that is a
distributed-systems answer with a distributed-systems price, paid in availability, every time.
Detecting divergence needs only that the two mandates' claims meet somewhere.

In Certificate Transparency the unsolved part of exactly this problem is gossip: getting one
party's view of a log in front of someone who can compare it with another's. Here there is a
channel nobody else has. **The attester is the gossip.** Both mandates already trust the same TEE
-- that is the entire point of the system -- and that TEE will sign over whatever it is shown. So
a single hardware report can carry BOTH mandates' claimed heads, at one moment, under a key that
belongs to neither of them.

    bundle = [ {mandate A, size, root}, {mandate B, size, root} ]
    the guest binds SHA-256(bundle) into REPORT_DATA; AMD signs the report

Afterwards, either mandate -- or an auditor, or the workload owner -- holds one AMD-signed
statement that both mandates claimed those ledger states simultaneously. Neither had to trust the
other, neither had to be online for the other, and no consensus ran. If A later produces a history
that its own head in that bundle does not extend, the report is the evidence.

This does not stop two mandates admitting different instances. Nothing short of consensus does.
It makes doing so leave a mark that the party who did it cannot remove.
"""
import hashlib, json, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .receipt import canonical, verify_sth

BUNDLE_VERSION = 1

def mandate_id(spki_der: bytes) -> str:
    """A short, stable name for a mandate: the hash of the key it signs heads with."""
    return hashlib.sha256(spki_der).hexdigest()[:32]

def bundle_entries(pairs):
    """pairs: [(mandate_spki, sth)] -> the canonical entry list, sorted so anyone rebuilds it."""
    return sorted(({"m": mandate_id(spki), "size": sth["size"], "root": sth["root"]}
                   for spki, sth in pairs), key=lambda e: (e["m"], e["size"], e["root"]))

def bundle_commitment(entries) -> bytes:
    """The 32 bytes the attester binds. A single mandate is just a bundle of one."""
    return hashlib.sha256(canonical({"v": BUNDLE_VERSION, "entries": entries})).digest()

def make_bundle(pairs):
    """Returns (commitment, entries). Each STH is verified first: a bundle of unsigned claims
    would be worth nothing, since anyone could put any root in it."""
    for spki, sth in pairs:
        verify_sth(spki, sth)
    entries = bundle_entries(pairs)
    return bundle_commitment(entries), entries

def verify_bundle(commitment: bytes, entries) -> bool:
    return bundle_commitment(entries) == commitment

def entry_for(entries, spki_der):
    mid = mandate_id(spki_der)
    return next((e for e in entries if e["m"] == mid), None)

# ---- cross-witnessing, for when the mandates can also talk directly ----
def cross_witness(signing_key, peer_spki, peer_sth, at=None):
    """One mandate's signed record of another's head. Weaker than the hardware bundle, because
    the observer is a party to the system; useful when the two can reach each other."""
    verify_sth(peer_spki, peer_sth)
    at = int(time.time() if at is None else at)
    body = {"v": BUNDLE_VERSION, "peer": mandate_id(peer_spki),
            "size": peer_sth["size"], "root": peer_sth["root"], "at": at}
    body["sig"] = signing_key.sign(canonical(_unsigned(body)), ec.ECDSA(hashes.SHA256())).hex()
    return body

def _unsigned(body):
    return {k: v for k, v in body.items() if k != "sig"}

def verify_cross_witness(observer_spki, statement):
    pub = serialization.load_der_public_key(observer_spki)
    pub.verify(bytes.fromhex(statement["sig"]), canonical(_unsigned(statement)),
               ec.ECDSA(hashes.SHA256()))
    return True

def divergence(peer_spki, claimed_size, claimed_root_hex, later_sth, proof):
    """Did the peer's log really grow from the state someone witnessed, to the one it shows now?

    `proof` is whatever consistency proof the peer was willing to give. Returns (diverged, reason).
    """
    from .log import verify_consistency
    verify_sth(peer_spki, later_sth)
    if claimed_size == later_sth["size"]:
        if claimed_root_hex == later_sth["root"]:
            return False, "same head"
        return True, "same size, different root: the peer signed two histories"
    if claimed_size > later_sth["size"]:
        return True, "the peer's log has shrunk, which an append-only log cannot do"
    if proof is None:
        return True, "the peer offered no proof that it extends the head that was witnessed"
    try:
        ok = verify_consistency(bytes.fromhex(claimed_root_hex), claimed_size,
                                bytes.fromhex(later_sth["root"]), later_sth["size"],
                                [bytes.fromhex(p) for p in proof])
    except Exception:
        ok = False
    if ok:
        return False, "the peer's log extends the witnessed head"
    return True, ("the peer cannot show its log extends a head it was witnessed claiming: "
                  "that witness is the evidence")
