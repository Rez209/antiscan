"""
Engine 3: HeuristicScan
  - Shannon entropy (high entropy -> packed/encrypted payload)
  - magic-byte vs file-extension mismatch
  - double-extension masquerade (invoice.pdf.exe)
"""
import math
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engines.protocol import poll_loop

ENGINE_NAME = "HeuristicScan"


def sniff_mime(data: bytes) -> str:
    """Tiny magic-byte sniffer — no external libmagic/DLL dependency,
    so this works identically on Windows/Linux/Mac with zero extra installs."""
    if data[:2] == b"MZ":
        return "application/x-dosexec"
    if data[:4] == b"\x7fELF":
        return "application/x-executable"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe"):
        return "application/x-mach-binary"
    if data[:4] == b"PK\x03\x04":
        return "application/zip"  # also covers docx/xlsx/pptx/jar (OOXML/zip-based)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "application/x-ole-storage"  # legacy .doc/.xls/.ppt
    if data[:4] == b"%PDF":
        return "application/pdf"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    return "application/octet-stream"


ENTROPY_SUSPICIOUS = 7.2   # bits/byte, out of max 8.0
EXE_LIKE_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
DOC_LIKE_EXT = {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".doc", ".docx", ".xlsx"}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan(path: Path):
    data = path.read_bytes()
    reasons = []
    score = 0.0

    ent = shannon_entropy(data)
    if ent >= ENTROPY_SUSPICIOUS and len(data) > 256:
        reasons.append(f"high entropy {ent:.2f}/8.0 (packed/encrypted?)")
        score = max(score, 0.55)

    mime = sniff_mime(data)

    suffixes = [s.lower() for s in path.suffixes]
    claimed_ext = suffixes[-1] if suffixes else ""

    is_exe_content = mime in ("application/x-dosexec", "application/x-executable", "application/x-mach-binary")
    if is_exe_content and claimed_ext in DOC_LIKE_EXT:
        reasons.append(f"content is executable ({mime}) but extension claims '{claimed_ext}'")
        score = max(score, 0.9)

    if len(suffixes) >= 2 and suffixes[-2] in DOC_LIKE_EXT and suffixes[-1] in EXE_LIKE_EXT:
        reasons.append(f"double-extension masquerade: '{''.join(suffixes)}'")
        score = max(score, 0.85)

    if not reasons:
        return "clean", f"no heuristic triggered (mime={mime}, entropy={ent:.2f})", 0.0

    verdict = "malicious" if score >= 0.8 else "suspicious"
    return verdict, "; ".join(reasons), score


if __name__ == "__main__":
    poll_loop(ENGINE_NAME, scan)