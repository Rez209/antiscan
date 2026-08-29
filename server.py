"""
Antiscan — host web server.
"""
import hashlib
import json
import time
import uuid
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, jsonify

from engines.protocol import INCOMING_DIR, RESULTS_DIR, HISTORY_DIR

ENGINES = ["SignatureScan", "YaraScan", "HeuristicScan", "HashReputation"]
SCAN_TIMEOUT_S = 20
MAX_UPLOAD_MB = 50

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


def submit_job(file_storage) -> str:
    job_id = uuid.uuid4().hex[:12]
    job_dir = INCOMING_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    filename = file_storage.filename or "unnamed"
    safe_name = filename.replace("/", "_").replace("\\", "_")
    dest = job_dir / safe_name
    file_storage.save(dest)
    return job_id


def collect_verdicts(job_id: str, timeout: float = SCAN_TIMEOUT_S):
    result_dir = RESULTS_DIR / job_id
    deadline = time.time() + timeout
    verdicts = {}
    while time.time() < deadline and len(verdicts) < len(ENGINES):
        for engine in ENGINES:
            if engine in verdicts:
                continue
            f = result_dir / f"{engine}.json"
            if f.exists():
                try:
                    verdicts[engine] = json.loads(f.read_text())
                except Exception:
                    pass
        if len(verdicts) < len(ENGINES):
            time.sleep(0.3)
    for engine in ENGINES:
        if engine not in verdicts:
            verdicts[engine] = {
                "engine": engine, "job_id": job_id, "verdict": "timeout",
                "detail": "no response within timeout", "score": 0.0, "scan_ms": None,
            }
    return verdicts


def aggregate(verdicts: dict):
    flagged = [e for e, v in verdicts.items() if v["verdict"] in ("malicious", "suspicious")]
    malicious = [e for e, v in verdicts.items() if v["verdict"] == "malicious"]
    if malicious:
        overall = "malicious"
    elif flagged:
        overall = "suspicious"
    else:
        overall = "clean"
    return {
        "overall": overall,
        "detections": len(flagged),
        "total": len(ENGINES),
        "flagged_by": flagged,
    }


def save_history(job_id, filename, file_hash, size, verdicts, summary):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "job_id": job_id, "filename": filename, "sha256": file_hash,
        "size": size, "verdicts": verdicts, "summary": summary,
        "ts": time.time(),
    }
    (HISTORY_DIR / f"{job_id}.json").write_text(json.dumps(entry, indent=2))


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    f = request.files.get("file")
    if not f or f.filename == "":
        return redirect(url_for("index"))

    job_id = submit_job(f)
    job_file = next((p for p in (INCOMING_DIR / job_id).iterdir() if p.is_file()), None)
    data = job_file.read_bytes()
    file_hash = hashlib.sha256(data).hexdigest()

    verdicts = collect_verdicts(job_id)
    summary = aggregate(verdicts)
    save_history(job_id, job_file.name, file_hash, len(data), verdicts, summary)

    return render_template(
        "result.html",
        job_id=job_id,
        filename=job_file.name,
        sha256=file_hash,
        size=len(data),
        verdicts=verdicts,
        summary=summary,
    )


@app.route("/history", methods=["GET"])
def history():
    entries = []
    for f in sorted(HISTORY_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            entries.append(json.loads(f.read_text()))
        except Exception:
            continue
    return render_template("history.html", entries=entries)


@app.route("/api/status")
def api_status():
    return jsonify({
        "engines": ENGINES,
        "incoming_jobs": len(list(INCOMING_DIR.iterdir())) if INCOMING_DIR.exists() else 0,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)