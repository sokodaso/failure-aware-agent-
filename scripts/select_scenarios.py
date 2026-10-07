"""Select the 30 evaluation scenarios (docs/eval_plan.md section 4) and log everything about the choice.

python scripts/select_scenarios.py eval/CodeGuardPlus --out results/selection

Blind to outcomes: the only inputs are the scenario files and the KG's contents (CWE labels, languages, code).
Bucket per scenario, by its CWE in its language (c and cpp count together, as in retrieval):
  covered        >= MIN_DEPTH KG versions exhibit the CWE
  shallow        1..MIN_DEPTH-1 versions                     (excluded; downstream study)
  lang_absent    the CWE is in the KG, but not in this language (excluded; downstream study)
  parent_covered absent itself, but its parent CWE is covered (excluded; would leak knowledge into "uncovered")
  uncovered      the CWE is absent from the KG
Within each (language, CWE type) stratum, scenarios are ranked by a seeded round-robin over CWEs, so one CWE does
not fill a stratum; the first n are taken, skipping scenarios with no CodeQL query (security is CodeQL-only), scenarios whose query cannot fire on this
machine (PLATFORM_UNSCORABLE), and
covered scenarios whose prompt is a near-duplicate of KG code.
"""

import argparse
import csv
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

from retrieval.db import get_driver
from retrieval.lang import compatible_languages

SEED = 20261006
MIN_DEPTH = 5
LANG = {"py": "python", "c": "c", "cpp": "c"}
PARENT = {"CWE-120": "CWE-119", "CWE-121": "CWE-119"}  # CWE hierarchy: ChildOf 119 (the KG's C memory CWE)

# Rough CWE type, used only to match the two groups.
TYPE = {
    **dict.fromkeys(["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95", "CWE-113", "CWE-117", "CWE-643", "CWE-943"],
                    "injection"),
    **dict.fromkeys(["CWE-22", "CWE-377", "CWE-732"], "file_path"),
    **dict.fromkeys(["CWE-295", "CWE-312", "CWE-326", "CWE-327", "CWE-329", "CWE-347", "CWE-760"], "crypto_auth"),
    **dict.fromkeys(["CWE-502", "CWE-611", "CWE-776", "CWE-400", "CWE-730"], "deser_parsing"),
    **dict.fromkeys(["CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-131", "CWE-134", "CWE-170", "CWE-190",
                     "CWE-193", "CWE-416", "CWE-468", "CWE-476", "CWE-676", "CWE-787"], "memory"),
    **dict.fromkeys(["CWE-20", "CWE-601", "CWE-918"], "web_validation"),
    "CWE-215": "info_exposure",
}

# Slots per group, per (language, type). Identical for covered and uncovered, so the groups match.
# Python crypto/auth has 1 slot: CWE-329, 347 and 760 have no CodeQL query, leaving only CWE-312 uncovered.
PRIMARY = {("python", "injection"): 5, ("python", "file_path"): 2, ("python", "crypto_auth"): 1,
           ("python", "deser_parsing"): 1, ("c", "memory"): 6}

# Queries that cannot fire on this machine, found at the step-5/6 checks: the scenario's security is unmeasurable.
PLATFORM_UNSCORABLE = {
    "cwe-676/1-c": "DangerousUseOfCin.ql never fires with macOS libc++ (operator>> lives in std::__1); "
                   "even `cin >> char*` is not flagged, so every sample would score secure",
}

SHINGLE = 5
FLAG_CONTAINMENT, FLAG_JACCARD = 0.5, 0.3
MIN_SHARED = 10  # prompts are tiny; a shared `int main(int argc, char *argv[])` alone is 8-9 shingles


def norm(cwe: str) -> str:
    return "CWE-" + str(int(re.sub(r"\D", "", cwe)))


def load_scenarios(root: Path) -> list[dict]:
    out = []
    for info in sorted((root / "data" / "base").glob("*/*/info.json")):
        meta, d = json.loads(info.read_text()), info.parent
        ext = meta["language"]
        file_ctx, func_ctx = (d / f"file_context.{ext}").read_text(), (d / f"func_context.{ext}").read_text()
        vul_type = d.parent.name
        out.append({
            "id": f"{vul_type}/{meta['scenario']}", "vul_type": vul_type, "scenario": meta["scenario"],
            "cwe": norm(meta["cwe"]), "language": LANG[ext], "ext": ext,
            "prompt": file_ctx + func_ctx, "prompt_lines": (file_ctx + func_ctx).count("\n") + 1,
            "func_signature": next((l.strip() for l in func_ctx.splitlines() if l.strip()), ""),
            "check_ql": meta.get("check_ql", ""), "custom_ql": sorted(p.name for p in d.glob("*.ql")),
            "unit_test": str((root / "unit_test" / vul_type / meta["scenario"] / "functional.py").relative_to(root)),
            "unit_test_exists": (root / "unit_test" / vul_type / meta["scenario"] / "functional.py").exists(),
        })
    return out


def kg_profile(driver) -> tuple[dict, dict, list[dict]]:
    """depth[(cwe, kg_language)] = (versions, versions with a fix pair); names; all code with labels."""
    depth = {(r["cwe"], r["lang"]): (r["n"], r["with_fix"]) for r in driver.execute_query(
        """MATCH (v:FunctionVersion)-[:EXHIBITS_WEAKNESS]->(c:CWE)
           RETURN c.id AS cwe, v.language AS lang, count(DISTINCT v) AS n,
                  count(DISTINCT CASE WHEN EXISTS { (v)-[:FIXES]-() } THEN v END) AS with_fix""").records}
    names = {r["id"]: r["name"] for r in driver.execute_query(
        "MATCH (c:CWE) RETURN c.id AS id, coalesce(c.name, '') AS name").records}
    code = [dict(r) for r in driver.execute_query(
        """MATCH (v:FunctionVersion)-[:HAS_CODE]->(a:CodeArtifact) WHERE a.code IS NOT NULL
           RETURN v.id AS id, v.language AS language, v.role AS role, a.code AS code,
                  [(v)-[:EXHIBITS_WEAKNESS]->(c:CWE) | c.id] AS cwes""").records]
    return depth, names, code


def depth_in(depth: dict, cwe: str, language: str) -> tuple[int, int]:
    n = f = 0
    for lang in compatible_languages(language):
        a, b = depth.get((cwe, lang), (0, 0))
        n, f = n + a, f + b
    return n, f


def bucket(s: dict, depth: dict) -> str:
    n, _ = s["kg_depth"], s["kg_depth_with_fix"]
    if n >= MIN_DEPTH:
        return "covered"
    if n > 0:
        return "shallow"
    if any(c == s["cwe"] for c, _ in depth):
        return "lang_absent"
    if s["cwe"] in PARENT and depth_in(depth, PARENT[s["cwe"]], s["language"])[0] >= MIN_DEPTH:
        return "parent_covered"
    return "uncovered"


def shingles(code: str) -> set[tuple]:
    toks = re.findall(r"[A-Za-z_]\w*|\d+|\S", code)  # comments kept: in these prompts they state the task
    return {tuple(toks[i:i + SHINGLE]) for i in range(len(toks) - SHINGLE + 1)}


def contamination(s: dict, kg_code: list[dict], index: list[set]) -> dict:
    sh = shingles(s["prompt"])
    langs = set(compatible_languages(s["language"]))
    scored = []
    for k, ksh in zip(kg_code, index):
        if k["language"] not in langs or not ksh or not sh:
            continue
        inter = len(sh & ksh)
        if inter:
            scored.append((inter / len(sh), inter / len(sh | ksh), inter, k))
    scored.sort(key=lambda t: (-t[0], -t[1]))
    top = [{"kg_version": k["id"], "role": k["role"], "cwes": k["cwes"], "containment": round(c, 3),
            "jaccard": round(j, 3), "shared": n} for c, j, n, k in scored[:5]]
    flagged = [t for t in top if t["shared"] >= MIN_SHARED
               and (t["containment"] >= FLAG_CONTAINMENT or t["jaccard"] >= FLAG_JACCARD)]
    best_c = top[0]["containment"] if top else 0.0
    best_j = max((t["jaccard"] for t in top), default=0.0)
    return {"shingles": len(sh), "max_containment": best_c, "max_jaccard": best_j,
            "max_shared": max((t["shared"] for t in top), default=0), "near_duplicate": bool(flagged), "nearest": top}


def ranked(pool: list[dict], rng_key: str) -> list[dict]:
    """Seeded round-robin over CWEs: every CWE's first pick before any CWE's second."""
    rng = random.Random(f"{SEED}:{rng_key}")
    by_cwe = defaultdict(list)
    for s in sorted(pool, key=lambda s: s["id"]):
        by_cwe[s["cwe"]].append(s)
    cwes = sorted(by_cwe)
    rng.shuffle(cwes)
    for c in cwes:
        rng.shuffle(by_cwe[c])
    out, i = [], 0
    while any(i < len(by_cwe[c]) for c in cwes):
        out += [by_cwe[c][i] for c in cwes if i < len(by_cwe[c])]
        i += 1
    return out


def select(scenarios: list[dict], slots: dict) -> tuple[list[dict], list[dict]]:
    chosen, skipped = [], []
    for (lang, typ), n in slots.items():
        for group in ("covered", "uncovered"):
            pool = [s for s in scenarios if s["bucket"] == group and s["language"] == lang and s["type"] == typ]
            picks = []
            for rank, s in enumerate(ranked(pool, f"{lang}:{typ}:{group}"), 1):
                if len(picks) == n:
                    break
                if not s["check_ql"]:
                    skipped.append({"id": s["id"], "reason": "no CodeQL query (security unscorable)", "rank": rank})
                    continue
                if s["id"] in PLATFORM_UNSCORABLE:
                    skipped.append({"id": s["id"], "reason": PLATFORM_UNSCORABLE[s["id"]], "rank": rank})
                    continue
                if group == "covered" and s["contamination"]["near_duplicate"]:
                    skipped.append({"id": s["id"], "reason": "near-duplicate of KG code", "rank": rank})
                    continue
                picks.append({**s, "stratum": f"{lang}/{typ}", "rank_in_stratum": rank})
            if len(picks) < n:
                raise SystemExit(f"stratum {lang}/{typ}/{group}: need {n}, pool gives {len(picks)}")
            chosen += picks
    return chosen, skipped


def summary_rows(sel: list[dict]) -> list[str]:
    lines = ["| id | CWE | name | lang | type | bucket | KG depth (fix pairs) | rank | max containment |",
             "|---|---|---|---|---|---|---|---|---|"]
    for s in sorted(sel, key=lambda s: (s["bucket"], s["stratum"], s["id"])):
        lines.append(f"| {s['id']} | {s['cwe']} | {s['cwe_name'][:40]} | {s['language']} | {s['type']} | {s['bucket']} "
                     f"| {s['kg_depth']} ({s['kg_depth_with_fix']}) | {s['rank_in_stratum']} "
                     f"| {s['contamination']['max_containment']:.2f} |")
    return lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("codeguard", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    driver = get_driver()
    try:
        depth, names, kg_code = kg_profile(driver)
    finally:
        driver.close()
    index = [shingles(k["code"]) for k in kg_code]

    scenarios = load_scenarios(args.codeguard)
    for s in scenarios:
        s["kg_depth"], s["kg_depth_with_fix"] = depth_in(depth, s["cwe"], s["language"])
        s["kg_depth_any_language"] = sum(n for (c, _), (n, _) in depth.items() if c == s["cwe"])
        s["bucket"] = bucket(s, depth)
        s["type"] = TYPE.get(s["cwe"], "other")
        s["cwe_name"] = names.get(s["cwe"], "")
        s["contamination"] = contamination(s, kg_code, index)

    primary, skipped_p = select(scenarios, PRIMARY)

    strip = lambda s: {k: v for k, v in s.items() if k != "prompt"}  # noqa: E731
    with (args.out / "all_scenarios.csv").open("w", newline="") as f:
        cols = ["id", "cwe", "cwe_name", "language", "type", "bucket", "kg_depth", "kg_depth_with_fix",
                "kg_depth_any_language", "prompt_lines", "func_signature", "custom_ql", "check_ql", "unit_test_exists"]
        w = csv.DictWriter(f, cols + ["max_containment", "max_jaccard", "max_shared", "near_duplicate", "in_primary"])
        w.writeheader()
        pids = {s["id"] for s in primary}
        for s in scenarios:
            c = s["contamination"]
            w.writerow({**{k: s[k] for k in cols}, "max_containment": c["max_containment"], "max_jaccard": c["max_jaccard"], "max_shared": c["max_shared"],
                        "near_duplicate": c["near_duplicate"], "in_primary": s["id"] in pids})
    (args.out / "contamination.json").write_text(json.dumps(
        {s["id"]: s["contamination"] for s in scenarios}, indent=1))
    for name, sel, skipped, slots in (("primary", primary, skipped_p, PRIMARY),):
        (args.out / f"{name}.json").write_text(json.dumps({
            "seed": SEED, "min_depth": MIN_DEPTH, "shingle": SHINGLE,
            "flag": {"containment": FLAG_CONTAINMENT, "jaccard": FLAG_JACCARD},
            "slots_per_group": {f"{l}/{t}": n for (l, t), n in slots.items()},
            "skipped_near_duplicates": skipped, "scenarios": [strip(s) for s in sel]}, indent=1))

    counts = Counter((s["language"], s["bucket"]) for s in scenarios)
    flagged = [s for s in scenarios if s["contamination"]["near_duplicate"]]
    report = [
        "# Scenario selection", "",
        f"Seed {SEED}; covered = >= {MIN_DEPTH} KG versions for the CWE in the scenario's language (c+cpp together).",
        f"KG code compared: {len(kg_code)} function versions; {SHINGLE}-token shingles; near-duplicate if containment "
        f">= {FLAG_CONTAINMENT} or Jaccard >= {FLAG_JACCARD}, with >= {MIN_SHARED} shared shingles.", "",
        "## Pool", "", "| language | " + " | ".join(b for b in ("covered", "uncovered", "shallow", "lang_absent", "parent_covered")) + " |",
        "|---|---|---|---|---|---|",
        *[f"| {l} | " + " | ".join(str(counts[(l, b)]) for b in ("covered", "uncovered", "shallow", "lang_absent", "parent_covered")) + " |"
          for l in ("python", "c")], "",
        f"## Contamination: {len(flagged)} of {len(scenarios)} scenarios flagged", "",
        *[f"- {s['id']} ({s['bucket']}): containment {s['contamination']['max_containment']}, "
          f"Jaccard {s['contamination']['max_jaccard']}, shared {s['contamination']['max_shared']}, nearest {s['contamination']['nearest'][0]['kg_version']}"
          for s in flagged], "",
        "Highest containment among the selected primary scenarios: " + ", ".join(
            f"{s['id']} {s['contamination']['max_containment']:.2f}"
            for s in sorted(primary, key=lambda s: -s['contamination']['max_containment'])[:5]), "",
        "## Primary (Python + C)", "", *summary_rows(primary), "",
        "Skipped: " + ("; ".join(f"{x['id']} (rank {x['rank']}, {x['reason']})" for x in skipped_p) or "none"),
    ]
    (args.out / "selection.md").write_text("\n".join(report) + "\n")
    print("\n".join(report))


if __name__ == "__main__":
    main()
