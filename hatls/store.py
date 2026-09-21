#!/usr/bin/env python3
"""Durable storage for the mandate's ledger.

Not all of the mandate's state deserves durability, and conflating the two is how the silent
downgrade happened.

  * The **ledger** -- which instance an identity was enrolled on, whether it is revoked, and the
    disputes recorded against it -- is an authority over an identity. Losing it changes what the
    mandate guarantees, so it must survive a restart.
  * The **session chains** are per connection. A connection does not outlive the process that
    serves it, so losing them costs nothing: the next connection starts its own chain at counter 0.
  * The **challenges** are nonces awaiting an enrolment. Losing them fails closed -- the enrolment
    is refused and retried -- so they stay in memory, and they expire on their own.

`FileStore` writes one JSON file per identity and replaces it atomically, so a crash mid-write
leaves either the old record or the new one, never a truncated file.
"""
import json, os, tempfile

class MemoryStore:
    """The default. Explicitly NOT durable: a restart loses the ledger."""
    durable = False
    def __init__(self): self._d = {}
    def get(self, key): return self._d.get(key)
    def put(self, key, record): self._d[key] = record
    def keys(self): return list(self._d)

class FileStore:
    """One atomically-replaced JSON file per identity, under `path`."""
    durable = True

    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def _file(self, key):
        if not all(c in "0123456789abcdef" for c in key):
            raise ValueError("ledger keys are hex identity strings")
        return os.path.join(self.path, f"{key}.json")

    def get(self, key):
        try:
            with open(self._file(key), encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return None

    def put(self, key, record):
        target = self._file(key)
        fd, tmp = tempfile.mkstemp(dir=self.path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record, fh, sort_keys=True)
                fh.flush(); os.fsync(fh.fileno())
            os.replace(tmp, target)          # atomic on POSIX
        except Exception:
            try: os.unlink(tmp)
            except OSError: pass
            raise

    def keys(self):
        return [f[:-5] for f in os.listdir(self.path) if f.endswith(".json")]
