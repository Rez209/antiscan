"""
Engine 1: SignatureScan
Classic byte/string signature matching against a small local malware
signature database (the same technique real antivirus engines use for
known threats). Fully offline — no external database download needed.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engines.protocol import poll_loop

ENGINE_NAME = "SignatureScan"

# Local signature DB: (name, byte pattern, score)
SIGNATURES = [
    ("EICAR-Test-File", rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", 1.0),
    ("Suspicious-PowerShell-Encoded", rb"-EncodedCommand", 0.6),
    ("Suspicious-PowerShell-DownloadString", rb"Net.WebClient", 0.5),
    ("Suspicious-JS-Eval-Base64", rb"eval(atob(", 0.6),
    ("Generic-Reverse-Shell-Marker", rb"/bin/sh -i", 0.8),
    ("Generic-Reverse-Shell-Marker-2", rb"nc -e /bin/", 0.8),
]

MAX_SCAN_BYTES = 20 * 1024 * 1024  # 20MB cap, matches what a real signature scanner would chunk


def scan(path: Path):
    data = path.read_bytes()[:MAX_SCAN_BYTES]
    hits = []
    best_score = 0.0
    for name, pattern, score in SIGNATURES:
        if pattern in data:
            hits.append(name)
            best_score = max(best_score, score)
    if not hits:
        return "clean", "no known signature matched", 0.0
    verdict = "malicious" if best_score >= 0.8 else "suspicious"
    return verdict, f"matched: {', '.join(hits)}", best_score


if __name__ == "__main__":
    poll_loop(ENGINE_NAME, scan)