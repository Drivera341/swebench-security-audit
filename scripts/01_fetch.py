"""Download SWE-bench Verified instances and each system's submitted patches.

Outputs
  work/swebench_verified.parquet   raw dataset (2 MB)
  data/instances.jsonl.gz          instance metadata + gold patch
  data/patches.jsonl.gz            one row per (system, instance)
  data/systems.json                display name, resolve rate, source folder
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import certifi
import pandas as pd

from common import (
    DATA, DATASET_URL, GH_RAW_EXPERIMENTS, S3_BASE, SYSTEMS, WORK, write_jsonl_gz,
)


SSL_CTX = ssl.create_default_context(cafile=certifi.where())


def get(url: str, retries: int = 4) -> bytes | None:
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=60, context=SSL_CTX) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                return None
        except (urllib.error.URLError, TimeoutError):
            pass
    raise RuntimeError(f"failed after {retries} attempts: {url}")


def fetch_dataset() -> pd.DataFrame:
    path = WORK / "swebench_verified.parquet"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(get(DATASET_URL))
    return pd.read_parquet(path)


def fetch_instance(folder: str, instance_id: str) -> dict:
    base = f"{S3_BASE}/{folder}/logs/{instance_id}"
    patch = get(f"{base}/patch.diff")
    report = get(f"{base}/report.json")
    resolved = None
    if report:
        # Some harness versions key the report by instance id, others don't.
        r = json.loads(report)
        resolved = bool(r.get(instance_id, r).get("resolved", False))
    return {
        "instance_id": instance_id,
        "patch": patch.decode("utf-8", "replace") if patch else "",
        "resolved_report": resolved,
    }


def main() -> None:
    df = fetch_dataset()
    ids = sorted(df["instance_id"])
    print(f"dataset: {len(ids)} instances")
    write_jsonl_gz(
        DATA / "instances.jsonl.gz",
        df[["instance_id", "repo", "base_commit", "patch", "test_patch",
            "FAIL_TO_PASS", "created_at", "version"]].to_dict("records"),
    )

    systems_meta, rows = {}, []
    with ThreadPoolExecutor(max_workers=32) as pool:
        for label, folder in SYSTEMS.items():
            raw = get(f"{GH_RAW_EXPERIMENTS}/{folder}/per_instance_details.json")
            details = json.loads(raw) if raw else None
            results = list(pool.map(lambda i: fetch_instance(folder, i), ids))
            n_resolved = 0
            for r in results:
                # The leaderboard's per-instance file is the source of truth when
                # present; otherwise fall back to the harness report.json.
                if details is not None:
                    r["resolved"] = bool(details.get(r["instance_id"], {}).get("resolved", False))
                else:
                    r["resolved"] = bool(r["resolved_report"])
                r["system"] = label
                n_resolved += r["resolved"]
                rows.append(r)
            mismatches = sum(
                r["resolved_report"] is not None and r["resolved_report"] != r["resolved"]
                for r in results
            )
            empty = sum(not r["patch"].strip() for r in results)
            systems_meta[label] = {
                "folder": folder,
                "resolved": n_resolved,
                "resolve_rate": n_resolved / len(ids),
                "empty_patches": empty,
                "report_mismatches": mismatches,
                "resolved_source": "per_instance_details" if details is not None else "report.json",
            }
            print(f"{label:18s} resolved={n_resolved:3d} empty={empty:3d} mismatches={mismatches}")

    write_jsonl_gz(DATA / "patches.jsonl.gz", rows)
    (DATA / "systems.json").write_text(json.dumps(systems_meta, indent=2))


if __name__ == "__main__":
    main()
