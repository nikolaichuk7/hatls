"""The playground is documentation that runs, so what it prints is checked like anything else."""
import os, subprocess, sys

ROOT = os.path.join(os.path.dirname(__file__), "..")

def _run(*args):
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run([sys.executable, os.path.join(ROOT, "examples", "attack.py"), *args],
                          capture_output=True, text=True, env=env, cwd=ROOT, timeout=300)

def test_every_attack_is_stopped_and_the_exit_code_says_so():
    out = _run()
    assert out.returncode == 0, out.stdout[-2000:]
    assert "attacks stopped: 13/13" in out.stdout

def test_the_restart_case_shows_the_default_and_both_fixes():
    """The README promises three outcomes here. If it prints two, the text is ahead of the code."""
    out = _run("restart")
    assert "restart, in-memory ledger (the default): got in" in out.stdout
    assert "[STOPPED ] restart, durable ledger" in out.stdout
    assert "[STOPPED ] restart, ledger lost, require_enrolment=True" in out.stdout
