"""
Engine 2: YaraScan
Structural / behavioral pattern matching using YARA rules (rules/basic.yar).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engines.protocol import poll_loop
import yara

ENGINE_NAME = "YaraScan"
RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "basic.yar"
_compiled = yara.compile(filepath=str(RULES_PATH))

SEVERITY_SCORE = {"test": 1.0, "suspicious": 0.65, "info": 0.1}


def scan(path: Path):
    matches = _compiled.match(str(path), timeout=10)
    if not matches:
        return "clean", "no YARA rule matched", 0.0
    names = []
    best_score = 0.0
    for m in matches:
        sev = m.meta.get("severity", "suspicious")
        best_score = max(best_score, SEVERITY_SCORE.get(sev, 0.5))
        names.append(m.rule)
    verdict = "malicious" if best_score >= 0.9 else "suspicious"
    return verdict, f"rules matched: {', '.join(names)}", best_score


if __name__ == "__main__":
    poll_loop(ENGINE_NAME, scan)