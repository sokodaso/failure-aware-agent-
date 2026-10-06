"""Score results/recall.jsonl: recall@k of the gold CWE per condition, split by KG coverage and language.

python scripts/score_recall.py results/recall.jsonl
"""

import collections
import json
import sys

from retrieval.db import get_driver

CONDITIONS = {"task": "task", "apis": "apis_rank", "comps": "comps"}
KS = (1, 3, 5)
PARENT = {"CWE-120": "CWE-119", "CWE-121": "CWE-119"}  # buffer-overflow children of the graph's CWE-119


def kg_cwes() -> set[str]:
    driver = get_driver()
    with driver.session() as s:
        ids = {r["id"] for r in s.run("MATCH (c:CWE)<-[:EXHIBITS_WEAKNESS]-(:FunctionVersion) RETURN DISTINCT c.id AS id")}
    driver.close()
    return ids


def hit(gold: str, ranked: list[str], k: int, lenient: bool) -> bool:
    return (PARENT.get(gold, gold) if lenient else gold) in ranked[:k]


def report(rows: list[dict], title: str, lenient: bool = False) -> None:
    print(f"\n{title}  (n={len(rows)})")
    if not rows:
        return
    print(f"  {'condition':8}" + "".join(f"  R@{k}" for k in KS) + "   avg #CWEs returned")
    for name, key in CONDITIONS.items():
        rec = [sum(hit(r["gold"], r[key], k, lenient) for r in rows) / len(rows) for k in KS]
        avg = sum(len(r[key]) for r in rows) / len(rows)
        print(f"  {name:8}" + "".join(f"  {x:.2f}" for x in rec) + f"   {avg:.1f}")


def main() -> None:
    rows = [json.loads(l) for l in open(sys.argv[1])]
    kg = kg_cwes()
    covered = [r for r in rows if r["gold"] in kg or PARENT.get(r["gold"]) in kg]
    strict_cov = [r for r in rows if r["gold"] in kg]
    print(f"{len(rows)} scenarios; KG covers {len(kg)} CWEs; {len(strict_cov)} scenarios have their gold CWE in the KG "
          f"({len(covered)} counting CWE-120/121 -> 119)")
    report(strict_cov, "PRIMARY: gold CWE in KG, strict match")
    report(covered, "gold in KG, CWE-120/121 counted as 119", lenient=True)
    for lang in ("python", "c"):
        report([r for r in strict_cov if r["language"] == lang], f"  by language: {lang}")
    by = collections.defaultdict(list)
    for r in strict_cov:
        by[r["gold"]].append(r)
    print("\nPer CWE, recall@3 (task / apis / comps):")
    for cwe, rs in sorted(by.items(), key=lambda kv: -len(kv[1])):
        cells = [sum(hit(r["gold"], r[key], 3, False) for r in rs) for key in CONDITIONS.values()]
        print(f"  {cwe:8} n={len(rs):2}  " + " / ".join(f"{c}/{len(rs)}" for c in cells))
    print("\nRank-1 wrong-CWE rate (the top result is a different CWE):")
    for name, key in CONDITIONS.items():
        print(f"  {name:8} {sum(bool(r[key]) and r[key][0] != r['gold'] for r in strict_cov) / len(strict_cov):.2f}")


if __name__ == "__main__":
    main()
