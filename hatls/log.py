#!/usr/bin/env python3
"""An append-only Merkle log, so the mandate's decisions can be checked by someone else.

The mandate is a trusted component that can lie in three ways: deny a decision it made, claim a
decision it did not make, or tell two relying parties different things. None of that is visible
from inside `present()`. A log fixes the first two and makes the third detectable:

  * every decision is a leaf, and a **receipt** carries an inclusion proof, so a relying party can
    show afterwards exactly what it was told;
  * a **consistency proof** between two heads shows the earlier log is a prefix of the later one,
    so entries cannot be rewritten or dropped;
  * two heads that neither extends is **equivocation**, with both signatures as evidence.

The hashing is RFC 6962: leaves are SHA-256(0x00 || entry), interior nodes SHA-256(0x01 || l || r),
and the empty tree is SHA-256 of nothing. Trees are recomputed from the leaf list rather than kept
incrementally: at the scale of one identity's decisions that is irrelevant, and it removes a whole
class of bug from code whose only job is to be checkable.
"""
import hashlib

def _h(*parts):
    d = hashlib.sha256()
    for p in parts: d.update(p)
    return d.digest()

def leaf_hash(entry: bytes) -> bytes: return _h(b"\x00", entry)
def node_hash(l: bytes, r: bytes) -> bytes: return _h(b"\x01", l, r)

def _k(n):
    """The largest power of two strictly less than n."""
    k = 1
    while k * 2 < n: k *= 2
    return k

def root(leaves):
    """MTH(D[n]) of RFC 6962."""
    n = len(leaves)
    if n == 0: return _h()
    if n == 1: return leaf_hash(leaves[0])
    k = _k(n)
    return node_hash(root(leaves[:k]), root(leaves[k:]))

def inclusion_proof(leaves, m):
    """PATH(m, D[n]): the hashes needed to walk leaf m up to the root."""
    n = len(leaves)
    if not 0 <= m < n: raise IndexError("no such leaf")
    if n == 1: return []
    k = _k(n)
    if m < k: return inclusion_proof(leaves[:k], m) + [root(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [root(leaves[:k])]

def verify_inclusion(entry, m, n, proof, expected_root):
    """Rebuild the root from the entry and its proof alone (RFC 6962 verifier)."""
    if not 0 <= m < n: return False
    node = leaf_hash(entry)
    fn, sn = m, n - 1
    for sibling in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            node = node_hash(sibling, node)
            while not (fn == 0 or fn & 1):
                fn >>= 1; sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1; sn >>= 1
    return sn == 0 and node == expected_root

def consistency_proof(leaves, m):
    """PROOF(m, D[n]): evidence that the first m leaves are a prefix of all n."""
    n = len(leaves)
    if not 0 < m <= n: raise IndexError("bad prefix size")
    if m == n: return []
    return _subproof(leaves, m, True)

def _subproof(leaves, m, b):
    n = len(leaves)
    if m == n: return [] if b else [root(leaves)]
    k = _k(n)
    if m <= k:
        return _subproof(leaves[:k], m, b) + [root(leaves[k:])]
    return _subproof(leaves[k:], m - k, False) + [root(leaves[:k])]

def verify_consistency(old_root, m, new_root, n, proof):
    """True if a log of size n with `new_root` really extends one of size m with `old_root`."""
    if m == n: return old_root == new_root and proof == []
    if not 0 < m < n or not proof: return False
    p = list(proof)
    if m & (m - 1) == 0:                 # m is a power of two: the old root is the first subtree
        p = [old_root] + p
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr); sr = node_hash(c, sr)
            while not (fn == 0 or fn & 1):
                fn >>= 1; sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return fr == old_root and sr == new_root and sn == 0

class MerkleLog:
    """The leaves plus the two operations a verifier needs."""
    def __init__(self, entries=None): self.entries = list(entries or [])

    def __len__(self): return len(self.entries)
    def append(self, entry: bytes):
        self.entries.append(entry)
        return len(self.entries) - 1, self.head()
    def head(self): return root(self.entries)
    def prove_inclusion(self, m): return inclusion_proof(self.entries, m)
    def prove_consistency(self, m): return consistency_proof(self.entries, m)
