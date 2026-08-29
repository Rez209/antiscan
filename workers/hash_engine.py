"""
Engine 4: HashReputation
Compares the file's SHA-256 against a small local reputation database.
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engines.protocol import poll_loop

ENGINE_NAME = "HashReputation"

DB_PATH = Path(__file__).resolve().parent.parent / "rules" / "hash_db.json"

DEFAULT_DB = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Test-File",
        "verdict": "malicious",
        "score": 1.0,
    }
}

if not DB_PATH.exists():
    DB_PATH.write_text(json.dumps(DEFAULT_DB, indent=2))


def load_db():
    try:
        return json.loads(DB_PATH.read_text())
    except Exception:
        return DEFAULT_DB


def scan(path: Path):
    data = path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    db = load_db()
    entry = db.get(sha256)
    if entry is None:
        return "clean", f"sha256 {sha256[:16]}... not present in reputation DB (unknown, not flagged)", 0.0
    return entry["verdict"], f"sha256 matched known entry '{entry['name']}'", entry["score"]


if __name__ == "__main__":
    poll_loop(ENGINE_NAME, scan)