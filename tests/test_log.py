"""The append-only log itself, checked the only way a Merkle tree should be: exhaustively.

A consistency proof is what stops the mandate rewriting its own history, so it gets a sweep rather
than a couple of examples: every prefix of every size, and every single-entry edit inside every
claimed prefix.
"""
import os, sys, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hatls.log import (MerkleLog, root, inclusion_proof, verify_inclusion,
                       consistency_proof, verify_consistency)

E = lambda i: f"entry-{i}".encode()
SIZES = range(1, 33)

def test_inclusion_holds_for_every_leaf_of_every_size():
    for n in SIZES:
        lg = MerkleLog([E(i) for i in range(n)]); r = lg.head()
        for m in range(n):
            assert verify_inclusion(lg.entries[m], m, n, lg.prove_inclusion(m), r), f"n={n} m={m}"

def test_inclusion_fails_on_a_tampered_entry():
    lg = MerkleLog([E(i) for i in range(17)]); r = lg.head()
    assert not verify_inclusion(b"forged", 5, 17, lg.prove_inclusion(5), r)

def test_inclusion_fails_at_the_wrong_index():
    lg = MerkleLog([E(i) for i in range(17)]); r = lg.head()
    assert not verify_inclusion(lg.entries[5], 6, 17, lg.prove_inclusion(5), r)

def test_inclusion_fails_against_someone_elses_root():
    lg = MerkleLog([E(i) for i in range(9)])
    assert not verify_inclusion(lg.entries[3], 3, 9, lg.prove_inclusion(3), os.urandom(32))

def test_consistency_holds_for_every_prefix_of_every_size():
    for n in SIZES:
        lg = MerkleLog([E(i) for i in range(n)])
        for m in range(1, n + 1):
            assert verify_consistency(root(lg.entries[:m]), m, lg.head(), n,
                                      lg.prove_consistency(m)), f"n={n} m={m}"

def test_no_rewritten_log_can_prove_it_merely_extended():
    """The property the whole thing rests on: a mandate that edits its past cannot hide it."""
    accepted = 0; attempts = 0
    for n in range(2, 18):
        honest = [E(i) for i in range(n)]
        for m in range(1, n):
            for edit in range(m):
                forged = list(honest); forged[edit] = b"TAMPERED"
                attempts += 1
                try:
                    if verify_consistency(root(honest[:m]), m, root(forged), n,
                                          consistency_proof(forged, m)):
                        accepted += 1
                except Exception:
                    pass
    assert attempts > 500
    assert accepted == 0, f"{accepted} rewritten logs passed as extensions"

def test_an_empty_prefix_is_refused():
    lg = MerkleLog([E(i) for i in range(4)])
    with pytest.raises(IndexError):
        lg.prove_consistency(0)

def test_the_empty_log_has_a_defined_head():
    import hashlib
    assert MerkleLog().head() == hashlib.sha256().digest()
