"""Paper figures (PDF for LaTeX, PNG for the README and project page)."""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
import pandas as pd

from common import DATA, FIGS, GOLD, ROOT, SYSTEMS

RES = DATA / "results"
DOCS = ROOT / "docs" / "figures"

# Reference palette (dataviz skill, light mode): slot 1 = models, slot 2 = human.
MODEL = "#2a78d6"
HUMAN = "#eb6834"
INK, INK_2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 8,
    "axes.edgecolor": GRID,
    "axes.linewidth": 0.8,
    "axes.labelcolor": INK_2,
    "axes.titlesize": 8.5,
    "axes.titleweight": "bold",
    "axes.titlecolor": INK,
    "xtick.color": INK_2,
    "ytick.color": INK,
    "xtick.major.size": 0,
    "ytick.major.size": 0,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.6,
    "axes.axisbelow": True,
    "figure.dpi": 200,
    "savefig.bbox": "tight",
    "pdf.fonttype": 42,
})


def save(fig, name: str) -> None:
    FIGS.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGS / f"{name}.pdf")
    fig.savefig(DOCS / f"{name}.png", dpi=220)
    plt.close(fig)


def fig_rates(summary: pd.DataFrame) -> None:
    metrics = [
        ("security_finding", "New security\nfinding", True),
        ("silent_except", "Silent exception\nhandler", True),
        ("edits_existing_tests", "Edited existing\ntests*", True),
        ("src_added", "Source lines\nadded (mean)", False),
    ]
    s = summary.set_index("system")
    models = s.drop(index=GOLD).sort_values("resolve_rate")
    gold = s.loc[GOLD]
    fig, axes = plt.subplots(1, len(metrics), figsize=(7.2, 2.9), sharey=True)
    y = range(len(models))
    for ax, (m, title, is_rate) in zip(axes, metrics):
        k = 100 if is_rate else 1
        col = f"{m}_rate" if is_rate else f"mean_{m}"
        rate = k * models[col]
        lo, hi = k * models[f"{m}_lo"], k * models[f"{m}_hi"]
        ax.hlines(y, lo, hi, color=MODEL, linewidth=1.4, alpha=0.55)
        ax.plot(rate, y, "o", color=MODEL, markersize=4.2, markeredgecolor="white",
                markeredgewidth=0.8, zorder=3)
        g = k * gold[col]
        ax.axvline(g, color=HUMAN, linewidth=1.4, zorder=2)
        ax.set_title(title, loc="left")
        ax.set_xlim(left=0)
        ax.grid(axis="y", visible=False)
        if is_rate:
            ax.xaxis.set_major_formatter(lambda v, _: f"{v:.0f}%")
        ax.tick_params(axis="x", labelsize=7)
    axes[0].set_yticks(list(y), [f"{n}  ({100 * r:.0f}%)" for n, r in models.resolve_rate.items()])
    handles = [
        plt.Line2D([], [], color=MODEL, marker="o", markersize=4.2, markeredgecolor="white",
                   linewidth=1.4, label="Model (dot = rate, line = 95% CI)"),
        plt.Line2D([], [], color=HUMAN, linewidth=1.4, label="Human-written fix (gold)"),
    ]
    fig.legend(handles=handles, loc="lower center", ncol=2, frameon=False,
               bbox_to_anchor=(0.55, -0.06), labelcolor=INK)
    fig.text(0.0, 1.0, "Models sorted by SWE-bench Verified resolve rate (in parentheses). "
             "*Forbidden by the agent's prompt; human fixes exclude tests by construction.",
             color=INK_2, fontsize=7, ha="left", va="bottom")
    fig.tight_layout(w_pad=0.6)
    save(fig, "fig_rates")


def fig_rules(rules: pd.DataFrame, top: int = 10) -> None:
    r = rules.pivot_table(index="rule_name", columns="group", values="per_1k_patches",
                          aggfunc="sum", fill_value=0)
    for col in ("Models (pooled)", GOLD):
        if col not in r:
            r[col] = 0.0
    r = r.sort_values("Models (pooled)", ascending=False).head(top).iloc[::-1]
    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    y = range(len(r))
    h = 0.36
    ax.barh([i + h / 2 + 0.02 for i in y], r["Models (pooled)"], height=h, color=MODEL,
            label="Models (pooled)")
    ax.barh([i - h / 2 - 0.02 for i in y], r[GOLD], height=h, color=HUMAN,
            label="Human-written fix (gold)")
    for i, (mv, gv) in enumerate(zip(r["Models (pooled)"], r[GOLD])):
        ax.text(mv + 0.3, i + h / 2 + 0.02, f"{mv:.1f}", va="center", fontsize=6.5, color=INK_2)
    ax.set_yticks(list(y), r.index)
    ax.set_xlabel("Introduced findings per 1,000 patches")
    ax.grid(axis="y", visible=False)
    ax.legend(frameon=False, loc="lower right", labelcolor=INK)
    save(fig, "fig_rules")


# Hand-placed label offsets (points) so names never collide; GPT-5.2 and
# GPT-5.2 Codex land on the identical point and share one label.
LABELS = {
    "GPT-5.2": ((-6, 4), "right", "GPT-5.2, GPT-5.2 Codex"),
    "GPT-5.2 Codex": None,
    "Kimi K2.5": ((-6, 3), "right", None),
    "Claude 4.5 Sonnet": ((-5, -10), "right", None),
    "Claude 4.6 Opus": ((5, 3), "left", None),
    "MiniMax M2.5": ((5, -9), "left", None),
    "GLM-5": ((0, -11), "center", None),
}


def fig_resolve_vs_sec(summary: pd.DataFrame) -> None:
    s = summary.set_index("system").drop(index=GOLD)
    gold = summary.set_index("system").loc[GOLD]
    fig, ax = plt.subplots(figsize=(3.8, 2.9))
    x, y = 100 * s.resolve_rate, 100 * s.security_finding_rate
    gy = 100 * gold.security_finding_rate
    ax.axhline(gy, color=HUMAN, linewidth=1.4, zorder=1)
    ax.annotate("human-written fixes", (x.max() + 6, gy), xytext=(-2, 3), textcoords="offset points",
                color=INK_2, fontsize=6.5, va="bottom", ha="right")
    ax.plot(x, y, "o", color=MODEL, markersize=5, markeredgecolor="white",
            markeredgewidth=0.9, zorder=3)
    for name in s.index:
        spec = LABELS.get(name, ((5, 3), "left", None))
        if spec is None:
            continue
        (dx, dy), ha, text = spec
        ax.annotate(text or name, (x[name], y[name]), xytext=(dx, dy), textcoords="offset points",
                    fontsize=6, color=INK_2, ha=ha)
    ax.set_xlabel("SWE-bench Verified resolve rate")
    ax.set_ylabel("Patches with a new security finding")
    ax.xaxis.set_major_formatter(lambda v, _: f"{v:.0f}%")
    ax.yaxis.set_major_locator(matplotlib.ticker.MultipleLocator(0.5))
    ax.yaxis.set_major_formatter(lambda v, _: f"{v:.1f}%")
    ax.set_ylim(0, max(2.0, gy + 0.3))
    ax.set_xlim(x.min() - 3, x.max() + 6)
    save(fig, "fig_resolve_vs_sec")


def main() -> None:
    summary = pd.read_csv(RES / "summary_by_system.csv")
    rules = pd.read_csv(RES / "rule_counts.csv")
    fig_rates(summary)
    fig_resolve_vs_sec(summary)
    print("figures written to", FIGS, "and", DOCS)


if __name__ == "__main__":
    main()
