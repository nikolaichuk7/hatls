#!/usr/bin/env python3
"""Receipts: what a relying party keeps so the mandate cannot deny what it said.

The mandate is trusted and can lie in three ways. It can deny a decision it made, claim one it did
not, or tell two relying parties different things. A signed append-only log answers all three,
though not equally:

  * **Non-repudiation.** Every decision is a leaf. A receipt carries the leaf, its index, an
    inclusion proof, and a signed tree head, so the holder can show later exactly what it was told
    and that the mandate signed for a log containing it.
  * **No rewriting.** A consistency proof between two signed heads shows the earlier log is a
    prefix of the later one. A mandate that drops or edits a decision cannot produce one.
  * **Equivocation is detected, not prevented.** Nothing stops a mandate signing two heads that
    neither extends -- but the two signatures together are proof that it did, and that is the
    strongest property a single trusted component can offer about itself.

Identities are logged as SHA-256 of the identity key, not the key, so the log does not become a
directory of who is running what. That is a weaker privacy property than it sounds: an observer who
already knows a key can recognise it. A real deployment would want to think harder than this.
"""
import hashlib, json, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from .log import verify_inclusion, verify_consistency

STH_VERSION = 1

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def identity_tag(tik_pub: bytes) -> str:
    """What goes in the log instead of the identity key itself."""
    return hashlib.sha256(tik_pub).hexdigest()

def make_entry(kind, tik_pub, accepted, reason, instance=None, at=None, seq=None):
    """One decision, as the bytes that become a leaf.

    `seq` is the position this entry will occupy. Without it two decisions taken in the same second
    with the same verdict are byte-identical, and identical leaves are indistinguishable: a mandate
    could drop one and add another without breaking any consistency proof, and a receipt for one
    would verify as a receipt for the other. Binding the entry to its position removes both."""
    return canonical({"v": 1,
                      "seq": seq,
                      "at": int(time.time() if at is None else at),
                      "kind": kind,
                      "id": identity_tag(tik_pub),
                      "instance": instance.hex() if instance else None,
                      "accepted": bool(accepted),
                      "reason": reason})

def sth_bytes(size, root, at):
    return canonical({"v": STH_VERSION, "size": size, "root": root.hex(), "at": at})

def sign_sth(signing_key, size, root, at=None):
    """A Signed Tree Head: the mandate's word about the whole log at one moment."""
    at = int(time.time() if at is None else at)
    sth = {"v": STH_VERSION, "size": size, "root": root.hex(), "at": at}
    sth["sig"] = signing_key.sign(sth_bytes(size, root, at), ec.ECDSA(hashes.SHA256())).hex()
    return sth

def verify_sth(mandate_spki_der, sth):
    """True if this head really is the mandate's."""
    pub = serialization.load_der_public_key(mandate_spki_der)
    pub.verify(bytes.fromhex(sth["sig"]),
               sth_bytes(sth["size"], bytes.fromhex(sth["root"]), sth["at"]),
               ec.ECDSA(hashes.SHA256()))
    return True

def verify_receipt(mandate_spki_der, receipt):
    """Check a receipt end to end: the head is the mandate's, and the entry is in that log.

    Returns (ok, reason). A receipt that verifies is evidence the mandate can no longer walk back.
    """
    try:
        verify_sth(mandate_spki_der, receipt["sth"])
    except Exception as e:
        return False, f"tree head is not signed by this mandate: {e}"
    entry = bytes.fromhex(receipt["entry"])
    proof = [bytes.fromhex(p) for p in receipt["proof"]]
    root = bytes.fromhex(receipt["sth"]["root"])
    if not verify_inclusion(entry, receipt["index"], receipt["sth"]["size"], proof, root):
        return False, "entry is not in the log that head commits to"
    return True, "receipt verifies"

def verify_extension(mandate_spki_der, old_sth, new_sth, proof):
    """True if `new_sth` really extends `old_sth`, both being this mandate's."""
    verify_sth(mandate_spki_der, old_sth); verify_sth(mandate_spki_der, new_sth)
    return verify_consistency(bytes.fromhex(old_sth["root"]), old_sth["size"],
                              bytes.fromhex(new_sth["root"]), new_sth["size"],
                              [bytes.fromhex(p) for p in proof])

def is_equivocation(mandate_spki_der, sth_a, sth_b, proof_a_to_b=None, proof_b_to_a=None):
    """Two heads from one mandate where neither extends the other.

    The caller supplies whatever consistency proofs the mandate was willing to give. If it can
    produce neither, and both heads carry its signature, it has signed two histories."""
    verify_sth(mandate_spki_der, sth_a); verify_sth(mandate_spki_der, sth_b)
    if sth_a["root"] == sth_b["root"] and sth_a["size"] == sth_b["size"]:
        return False, "same head"
    lo, hi = (sth_a, sth_b) if sth_a["size"] <= sth_b["size"] else (sth_b, sth_a)
    proof = proof_a_to_b if lo is sth_a else proof_b_to_a
    if proof is not None:
        try:
            if verify_consistency(bytes.fromhex(lo["root"]), lo["size"],
                                  bytes.fromhex(hi["root"]), hi["size"],
                                  [bytes.fromhex(p) for p in proof]):
                return False, "one head extends the other; this is a consistent log"
        except Exception:
            pass
    return True, ("the mandate signed two heads and cannot show one extends the other: "
                  "this is equivocation, and both signatures are the evidence")
