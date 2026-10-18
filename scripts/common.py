"""Shared configuration and helpers for the audit pipeline."""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"  # small, committed artifacts
WORK = ROOT / "work"  # large, regenerable artifacts (gitignored)
FIGS = ROOT / "paper" / "figures"

DATASET_URL = (
    "https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified/"
    "resolve/main/data/test-00000-of-00001.parquet"
)
S3_BASE = "https://swe-bench-submissions.s3.amazonaws.com/bash-only"
GH_RAW_EXPERIMENTS = (
    "https://raw.githubusercontent.com/swe-bench/experiments/main/evaluation/verified"
)

# Every system below uses the same agent scaffold (mini-SWE-agent v2.0.0,
# bash-only track), so differences between rows come from the model rather
# than from tooling. Keys are short labels used in tables and figures.
SYSTEMS: dict[str, str] = {
    "Claude 4.5 Haiku": "20260217_mini-v2.0.0_claude-4-5-haiku-high",
    "Claude 4.5 Sonnet": "20260217_mini-v2.0.0_claude-4-5-sonnet-high",
    "Claude 4.5 Opus": "20260217_mini-v2.0.0_claude-4-5-opus-high",
    "Claude 4.6 Opus": "20260217_mini-v2.0.0_claude-4-6-opus",
    "GPT-5 mini": "20260217_mini-v2.0.0_gpt-5-mini",
    "GPT-5.2": "20260217_mini-v2.0.0_gpt-5-2-high",
    "GPT-5.2 Codex": "20260219_mini-v2.0.0_gpt-5-2-codex",
    "Gemini 3 Flash": "20260217_mini-v2.0.0_gemini-3-flash-high",
    # Excluded: 20260226_mini-v2.0.0_gemini-3-pro-high. Its published
    # per_instance_details.json marks every instance unresolved, while the
    # leaderboard reports 69.6% and the S3 harness reports give 70.6%, so its
    # per-instance outcomes cannot be reconciled.
    "DeepSeek V3.2": "20260217_mini-v2.0.0_deepseek-3-2-high",
    "GLM-5": "20260217_mini-v2.0.0_glm-5-high",
    "Kimi K2.5": "20260217_mini-v2.0.0_kimi-k2-5-high",
    "MiniMax M2.5": "20260217_mini-v2.0.0_minimax-2-5-high",
}
GOLD = "Human (gold)"

# Test suites live in `tests/` directories (and pytest's own top-level
# `testing/`). Library code such as `django/test/` or `sphinx/testing/` is
# deliberately *not* matched: those are test frameworks shipped to users.
TEST_PATH_RE = re.compile(
    r"(^|/)tests(/|$)|^testing/|(^|/)(test_|unittest_)[^/]*\.py$|_tests?\.py$|(^|/)conftest\.py$"
)


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH_RE.search(path))


def slug(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")


def write_jsonl_gz(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def read_jsonl_gz(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]
