"""Pre-registered analysis of the CodeGuard+ evaluation (docs/eval_plan.md section 7).

venv/bin/python scripts/analyze_eval.py results/eval/main

Reads index.jsonl (one row per scored run). Writes OUT/analysis/: report.md, results.json, per_scenario.csv.
Every interval is a seeded percentile bootstrap over scenarios (resampled within each group), never over samples.
"""

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr

ROOT = Path(__file__).resolve().parent.parent
SEED, B = 20261006, 10_000
ARMS = ("baseline", "v1", "v2")
GROUPS = ("covered", "uncovered")
TARGET = 0.20  # the effect size the plan says 15 scenarios per group can detect


def boot_mean(x: np.ndarray, rng) -> tuple[float, float]:
    idx = rng.integers(0, len(x), (B, len(x)))
    m = x[idx].mean(axis=1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def boot_diff(a: np.ndarray, b: np.ndarray, rng) -> tuple[float, float]:
    ma = a[rng.integers(0, len(a), (B, len(a)))].mean(axis=1)
    mb = b[rng.integers(0, len(b), (B, len(b)))].mean(axis=1)
    d = ma - mb
    return float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))


def est(x, rng) -> dict:
    x = np.asarray(x, float)
    lo, hi = boot_mean(x, rng)
    return {"mean": float(x.mean()), "ci": [lo, hi], "n": len(x)}


def pct(v: float) -> str:
    return f"{100 * v:+.1f}" if v is not None else "n/a"


def fmt(e: dict) -> str:
    return f"{100 * e['mean']:+.1f} [{100 * e['ci'][0]:+.1f}, {100 * e['ci'][1]:+.1f}]"


def verdict(diff: dict) -> str:
    lo, hi = diff["ci"]
    if lo > 0:
        return "supports H1" if diff["mean"] >= TARGET else "covered gain larger, but below the ~20-point target"
    if hi < 0:
        return "opposite direction: uncovered gain larger"
    return "inconclusive (interval includes zero; not evidence of no effect)"


def main() -> None:
    out = Path(sys.argv[1])
    rows = [json.loads(l) for l in (out / "index.jsonl").read_text().splitlines()]
    cfg = json.loads((out / "config.json").read_text())
    meta = {r["id"]: r for r in csv.DictReader((ROOT / "results" / "selection" / "all_scenarios.csv").open())}
    n_expected = len(cfg["scenarios"]) * len(ARMS) * cfg["samples"]
    if len(rows) != n_expected:
        raise SystemExit(f"index has {len(rows)} scored runs, expected {n_expected}; finish scoring first")

    by = defaultdict(list)
    for r in rows:
        by[(r["id"], r["arm"])].append(r)
    scen = sorted({r["id"] for r in rows})
    group = {s: meta[s]["bucket"] for s in scen}
    per = {}  # (scenario, arm) -> metrics
    for (s, a), rs in by.items():
        n = len(rs)
        func = sum(r["functional"] for r in rs)
        sp = sum(r["sec_pass"] for r in rs)
        harness = [r for r in rs if r.get("gold_rank") is not None or "retrieved" in r]
        per[(s, a)] = {
            "sec_pass": sp / n, "functional": func / n, "secure": sum(r["codeql_secure"] for r in rs) / n,
            "secure_given_functional": sp / func if func else None,
            "limits_exceeded": sum(r.get("exit_status") == "LimitsExceeded" for r in rs) / n,
            "no_file_or_unparsable": sum(r["score_status"] != "scored" for r in rs) / n,
            "prompt_lines_kept": float(np.mean([r.get("prompt_lines_kept", 0) for r in rs])),
            "agent_cost": float(np.mean([r.get("agent_cost") or 0 for r in rs])),
            "agent_steps": float(np.mean([r.get("agent_calls") or 0 for r in rs])),
            "harness_cost": float(np.mean([r.get("harness_cost") or 0 for r in rs])),
            "harness_tokens": float(np.mean([(r.get("harness_prompt_tokens") or 0) + (r.get("harness_completion_tokens") or 0)
                                             for r in rs])),
            "gold_top3": (sum(1 for r in harness if r.get("gold_rank") and r["gold_rank"] <= 3) / len(harness)
                          if harness else None),
            "gold_rank_mean": (float(np.mean([r["gold_rank"] for r in harness if r.get("gold_rank")]))
                               if any(r.get("gold_rank") for r in harness) else None),
            "rules": Counter(rule for r in rs for rule in r.get("finding_rules", [])),
        }

    rng = np.random.default_rng(SEED)
    res = {"config": {"seed": SEED, "bootstrap": B, "target": TARGET, "n_scenarios": len(scen),
                      "per_group": {g: sum(group[s] == g for s in scen) for g in GROUPS}}}

    def vec(metric, arm, g=None):
        return np.array([per[(s, arm)][metric] for s in scen if g is None or group[s] == g], float)

    # arm levels
    res["levels"] = {m: {a: {g: est(vec(m, a, g), rng) for g in GROUPS} for a in ARMS}
                     for m in ("sec_pass", "functional", "secure")}

    # H1 per harness arm, on the primary metric and on functional pass (over-restriction check)
    res["H1"] = {}
    for m in ("sec_pass", "functional"):
        for a in ("v1", "v2"):
            gains = {g: vec(m, a, g) - vec(m, "baseline", g) for g in GROUPS}
            lo, hi = boot_diff(gains["covered"], gains["uncovered"], rng)
            diff = {"mean": float(gains["covered"].mean() - gains["uncovered"].mean()), "ci": [lo, hi]}
            entry = {g: est(gains[g], rng) for g in GROUPS} | {"overall": est(np.concatenate(list(gains.values())), rng),
                                                                "difference": diff}
            if m == "sec_pass":
                entry["verdict"] = verdict(diff)
            res["H1"][f"{m}/{a}"] = entry

    # H2
    res["H2"] = {}
    for m in ("sec_pass", "functional"):
        d = {g: vec(m, "v2", g) - vec(m, "v1", g) for g in GROUPS}
        res["H2"][m] = {g: est(d[g], rng) for g in GROUPS} | {"overall": est(np.concatenate(list(d.values())), rng)}

    # secure given functional (scenarios with at least one functional sample in both arms)
    res["secure_given_functional"] = {}
    for a in ARMS:
        for g in GROUPS:
            v = [per[(s, a)]["secure_given_functional"] for s in scen if group[s] == g]
            v = [x for x in v if x is not None]
            res["secure_given_functional"][f"{a}/{g}"] = {"mean": float(np.mean(v)) if v else None, "n_scenarios": len(v)}

    # mediators and diagnostics
    med = {}
    for a in ("v1", "v2"):
        cov = [s for s in scen if group[s] == "covered"]
        gain = np.array([per[(s, a)]["sec_pass"] - per[(s, "baseline")]["sec_pass"] for s in cov])
        top3 = np.array([per[(s, a)]["gold_top3"] for s in cov], float)
        depth = np.array([float(meta[s]["kg_depth"]) for s in cov])
        rho_r, p_r = spearmanr(top3, gain) if np.ptp(top3) > 0 else (None, None)
        rho_d, p_d = spearmanr(depth, gain)
        med[a] = {"gold_top3_rate": {g: float(np.mean([per[(s, a)]["gold_top3"] for s in scen if group[s] == g]))
                                     for g in GROUPS},
                  "covered_gain_vs_gold_top3_spearman": [None if rho_r is None else float(rho_r),
                                                         None if p_r is None else float(p_r)],
                  "covered_gain_vs_kg_depth_spearman": [float(rho_d), float(p_d)]}
    res["mediators"] = med
    base = {s: per[(s, "baseline")]["sec_pass"] for s in scen}
    res["baseline_floor"] = [s for s in scen if base[s] == 0.0]
    res["baseline_ceiling"] = [s for s in scen if base[s] == 1.0]
    res["diagnostics"] = {a: {k: float(np.mean([per[(s, a)][k] for s in scen]))
                              for k in ("limits_exceeded", "no_file_or_unparsable", "prompt_lines_kept", "agent_cost",
                                        "agent_steps", "harness_cost", "harness_tokens")} for a in ARMS}
    res["codeql_rules"] = {a: dict(sum((per[(s, a)]["rules"] for s in scen), Counter()).most_common()) for a in ARMS}
    res["total_cost"] = {"agent": float(sum(r.get("agent_cost") or 0 for r in rows)),
                         "harness": float(sum(r.get("harness_cost") or 0 for r in rows))}

    # ---------------------------------------------------------------- outputs
    ad = out / "analysis"
    ad.mkdir(exist_ok=True)
    (ad / "results.json").write_text(json.dumps(res, indent=1))
    with (ad / "per_scenario.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "bucket", "stratum", "kg_depth"] + [f"{m}_{a}" for m in ("sec_pass", "functional", "secure")
                                                                for a in ARMS]
                   + ["gain_v1", "gain_v2", "v2_minus_v1", "gold_top3_v1", "gold_top3_v2",
                      "limits_exceeded_baseline", "limits_exceeded_v1", "limits_exceeded_v2",
                      "prompt_kept_baseline", "prompt_kept_v1", "prompt_kept_v2"])
        for s in scen:
            p = {a: per[(s, a)] for a in ARMS}
            w.writerow([s, group[s], meta[s].get("type"), meta[s]["kg_depth"]]
                       + [p[a][m] for m in ("sec_pass", "functional", "secure") for a in ARMS]
                       + [round(p["v1"]["sec_pass"] - p["baseline"]["sec_pass"], 3),
                          round(p["v2"]["sec_pass"] - p["baseline"]["sec_pass"], 3),
                          round(p["v2"]["sec_pass"] - p["v1"]["sec_pass"], 3),
                          p["v1"]["gold_top3"], p["v2"]["gold_top3"]]
                       + [p[a]["limits_exceeded"] for a in ARMS] + [round(p[a]["prompt_lines_kept"], 3) for a in ARMS])

    L = ["# CodeGuard+ evaluation: results", "",
         f"{len(scen)} scenarios ({res['config']['per_group']['covered']} covered, "
         f"{res['config']['per_group']['uncovered']} uncovered) x 3 arms x {cfg['samples']} samples = {len(rows)} runs. "
         f"Model {cfg['model']}. Intervals: 95% percentile bootstrap over scenarios ({B} resamples, seed {SEED}). "
         "Values are percentage points.", "",
         "## Levels (mean per-scenario rate, %)", "",
         "| metric | arm | covered | uncovered |", "|---|---|---|---|"]
    for m in ("sec_pass", "functional", "secure"):
        for a in ARMS:
            L.append(f"| {m} | {a} | " + " | ".join(f"{100 * res['levels'][m][a][g]['mean']:.1f}" for g in GROUPS) + " |")
    L += ["", "## H1: harness gain over baseline, covered vs uncovered (sec-pass@1)", "",
          "| arm | covered gain | uncovered gain | difference (covered - uncovered) | verdict |", "|---|---|---|---|---|"]
    for a in ("v1", "v2"):
        e = res["H1"][f"sec_pass/{a}"]
        L.append(f"| {a} | {fmt(e['covered'])} | {fmt(e['uncovered'])} | {fmt(e['difference'])} | {e['verdict']} |")
    L += ["", "Same on functional pass alone (does the harness over-restrict?):", "",
          "| arm | covered gain | uncovered gain | difference |", "|---|---|---|---|"]
    for a in ("v1", "v2"):
        e = res["H1"][f"functional/{a}"]
        L.append(f"| {a} | {fmt(e['covered'])} | {fmt(e['uncovered'])} | {fmt(e['difference'])} |")
    L += ["", "## H2: v2 - v1 (exploratory)", "", "| metric | overall | covered | uncovered |", "|---|---|---|---|"]
    for m in ("sec_pass", "functional"):
        e = res["H2"][m]
        L.append(f"| {m} | {fmt(e['overall'])} | {fmt(e['covered'])} | {fmt(e['uncovered'])} |")
    L += ["", "## Secure given functional (mean over scenarios with >= 1 functional sample)", "",
          "| arm | covered | uncovered |", "|---|---|---|"]
    for a in ARMS:
        L.append(f"| {a} | " + " | ".join(
            (f"{100 * x['mean']:.1f} (n={x['n_scenarios']})" if x["mean"] is not None else "n/a")
            for x in (res["secure_given_functional"][f"{a}/{g}"] for g in GROUPS)) + " |")
    L += ["", "## Mediators", ""]
    for a in ("v1", "v2"):
        m = med[a]
        r1, r2 = m["covered_gain_vs_gold_top3_spearman"], m["covered_gain_vs_kg_depth_spearman"]
        L.append(f"- {a}: gold CWE in the top 3 retrieved for {100 * m['gold_top3_rate']['covered']:.0f}% of covered "
                 f"runs ({100 * m['gold_top3_rate']['uncovered']:.0f}% uncovered, by construction). Within covered, "
                 f"gain vs gold-retrieved rate: Spearman {'n/a' if r1[0] is None else f'{r1[0]:.2f} (p={r1[1]:.2f})'}; "
                 f"gain vs KG depth: Spearman {r2[0]:.2f} (p={r2[1]:.2f}).")
    L += ["", f"Baseline at floor (0% sec-pass): {', '.join(res['baseline_floor']) or 'none'}.",
          f"Baseline at ceiling (100%): {', '.join(res['baseline_ceiling']) or 'none'}. Reported, not dropped.", "",
          "## Diagnostics (mean per run)", "",
          "| arm | step-limit hit | no file / unparsable | prompt lines kept | agent steps | agent $ | harness $ | harness tokens |",
          "|---|---|---|---|---|---|---|---|"]
    for a in ARMS:
        d = res["diagnostics"][a]
        L.append(f"| {a} | {100 * d['limits_exceeded']:.1f}% | {100 * d['no_file_or_unparsable']:.1f}% | "
                 f"{d['prompt_lines_kept']:.3f} | {d['agent_steps']:.1f} | {d['agent_cost']:.4f} | "
                 f"{d['harness_cost']:.4f} | {d['harness_tokens']:.0f} |")
    L += ["", f"Total API cost: agent ${res['total_cost']['agent']:.2f}, harness ${res['total_cost']['harness']:.2f}.",
          "", "## CodeQL findings by arm (samples flagged per rule)", ""]
    for a in ARMS:
        L.append(f"- {a}: " + (", ".join(f"{k} {v}" for k, v in res["codeql_rules"][a].items()) or "none"))
    L += ["", "## Per scenario (sec-pass@1 %, baseline / v1 / v2)", "", "| scenario | group | baseline | v1 | v2 |",
          "|---|---|---|---|---|"]
    for s in sorted(scen, key=lambda s: (group[s], s)):
        L.append(f"| {s} | {group[s]} | " + " | ".join(f"{100 * per[(s, a)]['sec_pass']:.0f}" for a in ARMS) + " |")
    (ad / "report.md").write_text("\n".join(L) + "\n")
    print("\n".join(L[:40]))


if __name__ == "__main__":
    main()
