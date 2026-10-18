"""Reconstruct the pre- and post-patch versions of every touched Python file.

For each (system, instance) the patch is applied to the files it touches, taken
from the repository at the instance's base commit. Only touched files are
materialized, which keeps the trees small enough to scan exhaustively.

Outputs
  work/base/<instance_id>/<path>                 pre-patch files (shared)
  work/trees/<system-slug>/<instance_id>/<path>  post-patch .py files
  data/apply_status.csv                          per-patch apply outcome
"""

from __future__ import annotations

import csv
import shutil
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import certifi
from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from common import DATA, GOLD, WORK, read_jsonl_gz, slug

SSL_CTX = ssl.create_default_context(cafile=certifi.where())
RAW = "https://raw.githubusercontent.com"


def strip_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def touched_sources(patch: str) -> list[str]:
    """Paths that must exist before the patch is applied."""
    try:
        ps = PatchSet(patch)
    except UnidiffParseError:
        return []
    return [strip_prefix(f.source_file) for f in ps if not f.is_added_file]


def fetch_base(repo: str, commit: str, path: str, dest: Path) -> bool:
    if dest.exists():
        return True
    url = f"{RAW}/{repo}/{commit}/{path}"
    for _ in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60, context=SSL_CTX) as r:
                data = r.read()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
        except (urllib.error.URLError, TimeoutError):
            pass
    return False


def apply_patch(patch: str, base_dir: Path, sources: list[str], out_dir: Path) -> str:
    """Apply `patch` in a scratch copy of the touched base files.

    Mirrors the SWE-bench harness: `git apply`, then `patch --fuzz=5` fallback.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for p in sources:
            src = base_dir / p
            if src.exists():
                (tmp / p).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, tmp / p)
        (tmp / "_patch.diff").write_text(patch)
        status = "git_apply"
        r = subprocess.run(
            ["git", "apply", "--whitespace=nowarn", "_patch.diff"],
            cwd=tmp, capture_output=True,
        )
        if r.returncode != 0:
            status = "patch_fuzz"
            r = subprocess.run(
                ["patch", "--batch", "--fuzz=5", "-p1", "-i", "_patch.diff"],
                cwd=tmp, capture_output=True,
            )
            if r.returncode != 0:
                return "failed"
        (tmp / "_patch.diff").unlink()
        for f in tmp.rglob("*.py"):
            dest = out_dir / f.relative_to(tmp)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
        return status


def main() -> None:
    instances = {r["instance_id"]: r for r in read_jsonl_gz(DATA / "instances.jsonl.gz")}
    patches = read_jsonl_gz(DATA / "patches.jsonl.gz")
    patches += [
        {"system": GOLD, "instance_id": i, "patch": r["patch"], "resolved": True}
        for i, r in instances.items()
    ]

    # 1) Fetch every pre-patch file any system touches, once.
    needed = {
        (p["instance_id"], src)
        for p in patches if p["patch"].strip()
        for src in touched_sources(p["patch"])
    }
    print(f"fetching {len(needed)} base files")

    def fetch(item):
        iid, path = item
        inst = instances[iid]
        return fetch_base(inst["repo"], inst["base_commit"], path, WORK / "base" / iid / path)

    with ThreadPoolExecutor(max_workers=24) as pool:
        ok = sum(pool.map(fetch, sorted(needed)))
    print(f"fetched {ok}/{len(needed)} (missing paths are typically files the patch deletes or invents)")

    # 2) Apply every patch.
    trees = WORK / "trees"
    shutil.rmtree(trees, ignore_errors=True)

    def build(p):
        if not p["patch"].strip():
            return p["system"], p["instance_id"], "empty"
        out = trees / slug(p["system"]) / p["instance_id"]
        out.mkdir(parents=True, exist_ok=True)
        status = apply_patch(
            p["patch"], WORK / "base" / p["instance_id"], touched_sources(p["patch"]), out
        )
        return p["system"], p["instance_id"], status

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(build, patches))

    with open(DATA / "apply_status.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["system", "instance_id", "status"])
        w.writerows(results)
    from collections import Counter
    print(Counter(s for *_, s in results))


if __name__ == "__main__":
    main()
