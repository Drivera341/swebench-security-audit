"""Aggregate per-patch signals into the statistics reported in the paper.

Outputs
  data/results/summary_by_system.csv   per-system rates with 95% Wilson CIs
  data/results/paired_vs_gold.csv      same-task comparison against human patches
  data/results/rule_counts.csv         introduced findings by rule
  data/results/stats.json              headline numbers
  paper/numbers.tex                    LaTeX macros for every number in the text
  paper/tables/main.tex                main results table
"""

from __future__ import annotations

import json
import math

import pandas as pd
from scipy import stats

from common import DATA, GOLD, ROOT, SYSTEMS

RES = DATA / "results"
PAPER = ROOT / "paper"

METRICS = {
    "security_finding": "New security finding",
    "silent_except": "Silent exception handler",
    "edits_existing_tests": "Edited existing tests",
    "unsanctioned_test_edit": "Unsanctioned test edit",
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def holm(pvals: list[float]) -> list[float]:
    order = sorted(range(len(pvals)), key=lambda i: pvals[i])
    adj, running = [0.0] * len(pvals), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvals) - rank) * pvals[i]))
        adj[i] = running
    return adj


def load() -> pd.DataFrame:
    df = pd.read_csv(RES / "patch_signals.csv")
    for col in ("resolved", "analyzed", "touches_tests", "edits_existing_tests",
                "adds_test_files", "scratch_artifact", "debug_print", "security_finding"):
        df[col] = df[col].astype(str).eq("True")
    df["silent_except"] = df["n_silent_except"] > 0
    df["bandit_medhigh"] = df["n_bandit_medhigh"] > 0
    df["semgrep_any"] = df["n_semgrep_any"] > 0
    df["unsanctioned_test_edit"] = df["test_edit_class"].eq("unsanctioned")
    df["test_edit_outside_graded"] = df["test_edit_outside_graded"].astype(str).eq("True")
    # A security finding is "task-intrinsic" when the human fix for the same
    # instance triggers the same rule; otherwise it is "model-only".
    f = pd.read_csv(RES / "new_findings.csv")
    f = f[(f.tool == "semgrep") | ((f.rule != "B101") & f.severity.isin(["MEDIUM", "HIGH"]))]
    gold_keys = set(zip(f[f.system == GOLD].instance_id, f[f.system == GOLD].rule))
    f["model_only"] = (f.system != GOLD) & ~pd.Series(
        [(i, r) in gold_keys for i, r in zip(f.instance_id, f.rule)], index=f.index)
    mo = set(zip(f[f.model_only].system, f[f.model_only].instance_id))
    df["model_only_sec"] = [(s, i) in mo for s, i in zip(df.system, df.instance_id)]
    return df


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    order = list(SYSTEMS) + [GOLD]
    for name in order:
        d = df[df.system == name]
        a = d[d.analyzed]
        r = {
            "system": name,
            "n": len(d),
            "n_analyzed": len(a),
            "resolve_rate": d.resolved.mean(),
            "mean_src_added": a.src_added.mean(),
            "src_added_lo": a.src_added.mean() - 1.96 * a.src_added.std() / math.sqrt(len(a)),
            "src_added_hi": a.src_added.mean() + 1.96 * a.src_added.std() / math.sqrt(len(a)),
            "median_src_added": a.src_added.median(),
            "sec_per_kloc": 1000 * (a.n_bandit_medhigh.sum() + a.n_semgrep_any.sum()) / max(a.src_added.sum(), 1),
        }
        for m in list(METRICS) + ["bandit_medhigh", "semgrep_any", "model_only_sec"]:
            k = int(a[m].sum())
            lo, hi = wilson(k, len(a))
            r.update({f"{m}_k": k, f"{m}_rate": k / len(a), f"{m}_lo": lo, f"{m}_hi": hi})
        ar = a[a.resolved]
        k = int(ar.security_finding.sum())
        r.update({"resolved_n": len(ar), "resolved_sec_k": k,
                  "resolved_sec_rate": k / len(ar) if len(ar) else math.nan})
        # Clean resolve: passes the tests *and* carries none of the signals the
        # tests cannot see. Denominator is all 500 instances, like the leaderboard.
        clean = ar[~(ar.security_finding | ar.silent_except | ar.edits_existing_tests)]
        r["clean_resolve_rate"] = len(clean) / len(d)
        rows.append(r)
    out = pd.DataFrame(rows)
    models = out.system != GOLD
    out.loc[models, "rank_resolve"] = out.loc[models, "resolve_rate"].rank(ascending=False, method="min")
    out.loc[models, "rank_clean"] = out.loc[models, "clean_resolve_rate"].rank(ascending=False, method="min")

    gold = df[(df.system == GOLD) & df.analyzed]
    for m in METRICS:
        pvals = []
        for name in SYSTEMS:
            a = df[(df.system == name) & df.analyzed]
            table = [[a[m].sum(), (~a[m]).sum()], [gold[m].sum(), (~gold[m]).sum()]]
            pvals.append(stats.fisher_exact(table)[1])
        adj = holm(pvals)
        out[f"{m}_p_holm"] = adj + [math.nan]
    return out


def paired_vs_gold(df: pd.DataFrame) -> pd.DataFrame:
    """Same task, both test-passing: does the model add findings the human fix didn't?"""
    gold = df[(df.system == GOLD) & df.analyzed].set_index("instance_id")
    rows = []
    for name in SYSTEMS:
        a = df[(df.system == name) & df.analyzed & df.resolved].set_index("instance_id")
        ids = a.index.intersection(gold.index)
        m, g = a.loc[ids, "security_finding"], gold.loc[ids, "security_finding"]
        b, c = int((m & ~g).sum()), int((~m & g).sum())
        p = stats.binomtest(b, b + c, 0.5).pvalue if b + c else math.nan
        rows.append({"system": name, "n_pairs": len(ids), "model_only": b,
                     "gold_only": c, "both": int((m & g).sum()), "p_exact": p})
    return pd.DataFrame(rows)


def rule_counts(df: pd.DataFrame) -> pd.DataFrame:
    f = pd.read_csv(RES / "new_findings.csv")
    f = f[(f.tool == "semgrep") | ((f.rule != "B101") & f.severity.isin(["MEDIUM", "HIGH"]))]
    f["group"] = f.system.where(f.system == GOLD, "Models (pooled)")
    n_patches = df[df.analyzed].groupby(df.system.where(df.system == GOLD, "Models (pooled)")).size()
    out = (f.groupby(["group", "tool", "rule_name"]).size().rename("count").reset_index())
    out["per_1k_patches"] = 1000 * out["count"] / out.group.map(n_patches)
    return out.sort_values(["group", "count"], ascending=[True, False])


def extra_parse_errors() -> int:
    """Post-patch files Bandit could not parse (syntax errors the patch introduced)."""
    from common import WORK
    return sum(
        len(json.loads(f.read_text())["errors"])
        for f in (WORK / "scans" / "bandit").glob("*.json") if f.stem != "base"
    )


def pct(x: float, digits: int = 1) -> str:
    return f"{100 * x:.{digits}f}"


def write_tex(summary: pd.DataFrame, paired: pd.DataFrame, extra: dict) -> None:
    (PAPER / "tables").mkdir(parents=True, exist_ok=True)
    s = summary.set_index("system")
    models = s.drop(index=GOLD)
    g = s.loc[GOLD]

    lines = [
        r"\begin{tabular}{lrrrrr}", r"\toprule",
        r"System & Resolved & New sec.\ finding & Silent except & Edits tests & Unsanctioned \\",
        r"\midrule",
    ]
    for name, r in models.sort_values("resolve_rate", ascending=False).iterrows():
        cells = [pct(r.resolve_rate)]
        for m in METRICS:
            v = pct(r[f"{m}_rate"])
            if r[f"{m}_p_holm"] < 0.05:
                v = r"\textbf{" + v + "}"
            cells.append(v)
        lines.append(f"{name} & " + " & ".join(cells) + r" \\")
    lines.append(r"\midrule")
    lines.append(f"{GOLD} & -- & " + " & ".join(pct(g[f'{m}_rate']) for m in METRICS) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (PAPER / "tables" / "main.tex").write_text("\n".join(lines) + "\n")

    lines = [r"\begin{tabular}{lrrrr}", r"\toprule",
             r"System & Resolved & Clean resolved & Drop & Rank change \\", r"\midrule"]
    for name, r in models.sort_values("clean_resolve_rate", ascending=False).iterrows():
        shift = int(r.rank_resolve - r.rank_clean)
        shift_s = f"+{shift}" if shift > 0 else (str(shift) if shift < 0 else "0")
        lines.append(f"{name} & {pct(r.resolve_rate)} & {pct(r.clean_resolve_rate)} & "
                     f"{pct(r.resolve_rate - r.clean_resolve_rate)} & {shift_s} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (PAPER / "tables" / "clean.tex").write_text("\n".join(lines) + "\n")

    lines = [r"\begin{tabular}{lrrrr}", r"\toprule",
             r"System & Pairs & Model only & Human only & $p$ (exact) \\", r"\midrule"]
    for _, r in paired.iterrows():
        p = "<0.001" if r.p_exact < 0.001 else f"{r.p_exact:.3f}"
        lines.append(f"{r.system} & {r.n_pairs} & {r.model_only} & {r.gold_only} & {p} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (PAPER / "tables" / "paired.tex").write_text("\n".join(lines) + "\n")

    macros = {k: v for k, v in extra.items()}
    tex = "% Generated by scripts/05_stats.py. Do not edit by hand.\n"
    for k, v in macros.items():
        if isinstance(v, int) and v >= 1000:
            v = f"{v:,}"
        tex += f"\\newcommand{{\\{k}}}{{{v}}}\n"
    (PAPER / "numbers.tex").write_text(tex)


def main() -> None:
    df = load()
    summary = summarize(df)
    paired = paired_vs_gold(df)
    rules = rule_counts(df)
    summary.to_csv(RES / "summary_by_system.csv", index=False)
    paired.to_csv(RES / "paired_vs_gold.csv", index=False)
    rules.to_csv(RES / "rule_counts.csv", index=False)

    models = df[df.system.isin(SYSTEMS)]
    ma = models[models.analyzed]
    sec_f = pd.read_csv(RES / "new_findings.csv")
    sec_f = sec_f[(sec_f.tool == "semgrep") | ((sec_f.rule != "B101") & sec_f.severity.isin(["MEDIUM", "HIGH"]))]
    gk = set(zip(sec_f[sec_f.system == GOLD].instance_id, sec_f[sec_f.system == GOLD].rule))
    sec_f["model_only"] = (sec_f.system != GOLD) & ~pd.Series(
        [(i, r) in gk for i, r in zip(sec_f.instance_id, sec_f.rule)], index=sec_f.index)
    gold = df[(df.system == GOLD) & df.analyzed]
    s = summary.set_index("system")
    ms = s.drop(index=GOLD)

    # Resolved vs. unresolved, pooled over models.
    res, unres = ma[ma.resolved], ma[~ma.resolved]
    p_ru = stats.fisher_exact([[res.security_finding.sum(), (~res.security_finding).sum()],
                               [unres.security_finding.sum(), (~unres.security_finding).sum()]])[1]
    rho, p_rho = stats.spearmanr(ms.resolve_rate, ms.security_finding_rate)
    rho_size, p_rho_size = stats.spearmanr(ms.mean_src_added, ms.security_finding_rate)
    pooled_b, pooled_c = int(paired.model_only.sum()), int(paired.gold_only.sum())

    extra = {
        "NModels": len(SYSTEMS),
        "NInstances": df.instance_id.nunique(),
        "NModelPatches": len(models),
        "NModelAnalyzed": len(ma),
        "NEmpty": int((models.apply_status == "empty").sum()),
        "NFailed": int((models.apply_status == "failed").sum()),
        "NResolvedPatches": int(res.shape[0]),
        "ResolvedSecPct": pct(res.security_finding.mean()),
        "ResolvedSecK": int(res.security_finding.sum()),
        "UnresolvedSecPct": pct(unres.security_finding.mean()),
        "ResUnresP": f"{p_ru:.3f}" if p_ru >= 0.001 else "<0.001",
        "GoldSecPct": pct(gold.security_finding.mean()),
        "GoldSecK": int(gold.security_finding.sum()),
        "ModelSecPct": pct(ma.security_finding.mean()),
        "ModelSecMinPct": pct(ms.security_finding_rate.min()),
        "ModelSecMaxPct": pct(ms.security_finding_rate.max()),
        "ModelSecMinName": ms.security_finding_rate.idxmin(),
        "ModelSecMaxName": ms.security_finding_rate.idxmax(),
        "GoldSilentPct": pct(gold.silent_except.mean()),
        "ModelSilentPct": pct(ma.silent_except.mean()),
        "ModelEditTestsPct": pct(ma.edits_existing_tests.mean()),
        "ModelEditTestsMaxPct": pct(ms.edits_existing_tests_rate.max()),
        "ModelEditTestsMaxName": ms.edits_existing_tests_rate.idxmax(),
        "NTestEdits": int(ma.edits_existing_tests.sum()),
        "NTestEditModels": int((ms.edits_existing_tests_k > 0).sum()),
        "NTestEditsAligned": int((ma.test_edit_class == "aligned").sum()),
        "NTestEditsUnsanctioned": int(ma.unsanctioned_test_edit.sum()),
        "NTestEditsUnsanctionedResolved": int((ma.unsanctioned_test_edit & ma.resolved).sum()),
        "NTestEditsResolved": int((ma.edits_existing_tests & ma.resolved).sum()),
        "NTestEditsOutsideGraded": int(ma.test_edit_outside_graded.sum()),
        "MiniSilentK": int(s.loc["GPT-5 mini", "silent_except_k"]),
        "MiniSilentPct": pct(s.loc["GPT-5 mini", "silent_except_rate"]),
        "MiniSilentResolvedK": int((ma[ma.system == "GPT-5 mini"].silent_except & ma[ma.system == "GPT-5 mini"].resolved).sum()),
        "OtherSilentMaxPct": pct(ms.drop(index="GPT-5 mini").silent_except_rate.max()),
        "NSilentOther": int(ma[ma.system != "GPT-5 mini"].silent_except.sum()),
        "NSecFindingsRaw": int(len(sec_f)),
        "NSecLinesUnique": int(sec_f[["instance_id", "path", "text"]].drop_duplicates().shape[0]),
        "NSecFindingsModel": int((sec_f.system != GOLD).sum()),
        "NSecFindingsIntrinsicPct": pct(1 - sec_f[sec_f.system != GOLD].model_only.mean()),
        "NModelOnlyLines": int(sec_f[sec_f.model_only].drop_duplicates(["instance_id", "path", "text"]).shape[0]),
        "NModelOnlyPatches": int(ma.model_only_sec.sum()),
        "NSecPatchesModel": int(ma.security_finding.sum()),
        "GPTTwoMeanAdded": f"{s.loc['GPT-5.2', 'mean_src_added']:.1f}",
        "GPTTwoAddedRatio": f"{s.loc['GPT-5.2', 'mean_src_added'] / s.loc[GOLD, 'mean_src_added']:.1f}",
        "GoldMeanAdded": f"{gold.src_added.mean():.1f}",
        "ModelMeanAdded": f"{ma.src_added.mean():.1f}",
        "GoldSecPerKloc": f"{s.loc[GOLD, 'sec_per_kloc']:.1f}",
        "ModelSecPerKloc": f"{1000 * (ma.n_bandit_medhigh.sum() + ma.n_semgrep_any.sum()) / ma.src_added.sum():.1f}",
        "RhoResolveSec": f"{rho:.2f}",
        "PRhoResolveSec": f"{p_rho:.2f}",
        "RhoSizeSec": f"{rho_size:.2f}",
        "PRhoSizeSec": f"{p_rho_size:.3f}" if p_rho_size >= 0.001 else "<0.001",
        "PairedModelOnly": pooled_b,
        "PairedGoldOnly": pooled_c,
        "PairedN": int(paired.n_pairs.sum()),
        "CleanDropMinPts": pct((ms.resolve_rate - ms.clean_resolve_rate).min()),
        "CleanDropMaxPts": pct((ms.resolve_rate - ms.clean_resolve_rate).max()),
        "CleanDropMaxName": (ms.resolve_rate - ms.clean_resolve_rate).idxmax(),
        "NRankChanged": int((ms.rank_resolve != ms.rank_clean).sum()),
        "NParseErrors": extra_parse_errors(),
    }
    write_tex(summary, paired, extra)
    (RES / "stats.json").write_text(json.dumps(extra, indent=2, default=str))
    print(json.dumps(extra, indent=2, default=str))




def write_appendix_tables() -> None:
    """Per-case tables for the appendix: every test edit and every model-only security line."""
    df = pd.read_csv(RES / "patch_signals.csv")
    t = df[df.test_edit_class.notna()].sort_values(["test_edit_class", "system", "instance_id"])
    tex = lambda s: str(s).replace("_", r"\_")
    lines = [r"\begin{tabular}{llcrl}", r"\toprule",
             r"Model & Instance & Resolved & Overlap & Class \\", r"\midrule"]
    for _, r in t.iterrows():
        cls = r.test_edit_class + (r"$^\dagger$" if str(r.test_edit_outside_graded) == "True" else "")
        lines.append(f"{r.system} & \\texttt{{{tex(r.instance_id)}}} & "
                     f"{'yes' if str(r.resolved) == 'True' else 'no'} & {float(r.test_edit_overlap):.2f} & {cls} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (PAPER / "tables" / "test_edits.tex").write_text("\n".join(lines) + "\n")

    tri = pd.read_csv(DATA / "triage" / "security_model_only.csv")
    nice = {"false_positive": "false positive", "benign_in_context": "benign in context",
            "benign_in_context_smell": "benign; code smell"}
    lines = [r"\begin{tabular}{llll}", r"\toprule", r"Model & Instance & Rule & Label \\", r"\midrule"]
    for _, r in tri.iterrows():
        lines.append(f"{r.system} & \\texttt{{{tex(r.instance_id)}}} & \\texttt{{{tex(r.rule)}}} & {nice[r.label]} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (PAPER / "tables" / "triage.tex").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
    write_appendix_tables()
