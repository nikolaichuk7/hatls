"""Every tracked Python file must at least parse.

Trivial, and it would have caught a real one: examples/client_mandate.py needs two confidential
VMs to run, so CI never executed it, and a careless bulk edit left it with stripped trailing commas
that survived until the next hardware run. Files CI cannot execute still get checked here.
"""
import os, sys, ast, glob, pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
FILES = sorted(p for p in glob.glob(os.path.join(ROOT, "**", "*.py"), recursive=True)
               if "/.git/" not in p and "__pycache__" not in p)

def test_there_are_sources_to_check():
    assert len(FILES) >= 10

@pytest.mark.parametrize("path", FILES, ids=[os.path.relpath(p, ROOT) for p in FILES])
def test_source_parses(path):
    ast.parse(open(path, encoding="utf-8").read(), filename=path)
