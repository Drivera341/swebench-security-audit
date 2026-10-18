"""Run Bandit and Semgrep over the pre-patch files and every system's post-patch tree.

Outputs
  work/scans/bandit/<target>.json
  work/scans/semgrep/<target>.json
where <target> is "base" or a system slug.
"""

from __future__ import annotations

import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import WORK

# p/python alone misses audit-style rules (eval, pickle, ...), so add p/security-audit.
SEMGREP_CONFIGS = ["p/python", "p/security-audit"]
BIN = Path(sys.executable).parent


def targets() -> dict[str, Path]:
    t = {"base": WORK / "base"}
    t.update({d.name: d for d in sorted((WORK / "trees").iterdir()) if d.is_dir()})
    return t


def run_bandit(name: str, path: Path) -> str:
    out = WORK / "scans" / "bandit" / f"{name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    subprocess.run(
        [BIN / "bandit", "-r", str(path), "-f", "json", "-o", str(out), "-q", "--exit-zero"],
        capture_output=True,
    )
    return f"bandit  {name:20s} {time.time() - start:6.1f}s"


def run_semgrep(name: str, path: Path) -> str:
    out = WORK / "scans" / "semgrep" / f"{name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    subprocess.run(
        [BIN / "semgrep", "scan", *[a for c in SEMGREP_CONFIGS for a in ("--config", c)],
         "--json", "--quiet",
         "--metrics=off", "--no-git-ignore", "--disable-version-check",
         "--x-ignore-semgrepignore-files", "--max-target-bytes=5000000",
         "--include=*.py", "-j", "8", "-o", str(out), str(path)],
        capture_output=True,
    )
    return f"semgrep {name:20s} {time.time() - start:6.1f}s"


def main() -> None:
    t = targets()
    with ThreadPoolExecutor(max_workers=6) as pool:
        for line in pool.map(lambda kv: run_bandit(*kv), t.items()):
            print(line, flush=True)
    for name, path in t.items():
        print(run_semgrep(name, path), flush=True)


if __name__ == "__main__":
    main()
