"""
Antiscan shared protocol.

Mirrors the original architecture: the host web server drops a submitted
file into a shared "incoming" folder as its own job directory. Each engine
worker is an independent process (originally: a separate VM with its own
antivirus) that polls the shared folder, and once it notices a new job,
scans the file and writes its verdict back into the shared "results"
folder for that job. Nothing talks to anything else directly — the
filesystem *is* the API, exactly like the shared folder in the original
build.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SHARED_ROOT = BASE_DIR / "shared"
INCOMING_DIR = SHARED_ROOT / "incoming"
RESULTS_DIR = SHARED_ROOT / "results"
HISTORY_DIR = SHARED_ROOT / "history"

for d in (INCOMING_DIR, RESULTS_DIR, HISTORY_DIR):
    d.mkdir(parents=True, exist_ok=True)


@dataclass
class Verdict:
    engine: str
    job_id: str
    filename: str
    verdict: str          # "clean" | "malicious" | "suspicious" | "error"
    detail: str            # human readable reason
    score: float            # 0.0 (clean) - 1.0 (definitely malicious)
    scan_ms: int

    def write(self):
        out = RESULTS_DIR / self.job_id / f"{self.engine}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2))
        tmp.rename(out)  # atomic-ish rename so the server never reads a half-written file


def job_dirs():
    """List job directories currently sitting in incoming/, oldest first."""
    if not INCOMING_DIR.exists():
        return []
    dirs = [p for p in INCOMING_DIR.iterdir() if p.is_dir()]
    return sorted(dirs, key=lambda p: p.stat().st_mtime)


def job_file(job_dir: Path) -> Path | None:
    files = [p for p in job_dir.iterdir() if p.is_file() and p.name != "meta.json"]
    return files[0] if files else None


def already_scanned(job_id: str, engine: str) -> bool:
    return (RESULTS_DIR / job_id / f"{engine}.json").exists()


def poll_loop(engine_name: str, scan_fn, interval: float = 0.5):
    """Generic worker main loop: watch incoming/, scan new jobs, write verdicts."""
    print(f"[{engine_name}] worker started, watching {INCOMING_DIR}")
    while True:
        for job_dir in job_dirs():
            job_id = job_dir.name
            if already_scanned(job_id, engine_name):
                continue
            f = job_file(job_dir)
            if f is None:
                continue
            t0 = time.time()
            try:
                verdict, detail, score = scan_fn(f)
            except Exception as e:  # an engine crashing must not take down the others
                verdict, detail, score = "error", f"{type(e).__name__}: {e}", 0.0
            scan_ms = int((time.time() - t0) * 1000)
            Verdict(
                engine=engine_name,
                job_id=job_id,
                filename=f.name,
                verdict=verdict,
                detail=detail,
                score=score,
                scan_ms=scan_ms,
            ).write()
            print(f"[{engine_name}] {job_id}/{f.name} -> {verdict} ({detail})")
        time.sleep(interval)