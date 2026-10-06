"""Does the labelled CWE come back from the KG? Recall@k for three retrieval granularities, no agent involved.

python scripts/retrieval_recall.py eval/CodeGuardPlus --out results/recall.jsonl [--limit N]

Per CodeGuard+ scenario (a code-completion prefix with a gold CWE) the same drafted code feeds every condition:
  task   one query: LLM summary of what the function must do          (v1 style, no APIs)
  apis   the same query + the APIs called by the draft                   (v2)
  comps  one query per failure-boundary component of the draft, merged   (v3)
Needs v3 (split_components, gather_components), which was removed from the harness after commit d40f5b7;
run it at that commit to reproduce.
LLM output is cached in the results file, so reruns and re-scoring cost nothing.
"""

import argparse
import json
import re
from pathlib import Path

from harness.draft import draft_code, extract_apis, split_components
from harness.knowledge import gather_components
from harness.llm import OpenAILLM
from retrieval.api import retrieve as kg_retrieve
from retrieval.db import get_driver
from retrieval.search import Embedder

LANG = {"py": "python", "c": "c", "cpp": "c"}  # the retrieval layer treats c/cpp as compatible
PARENT = {"CWE-120": "CWE-119", "CWE-121": "CWE-119"}  # buffer-overflow children of the graph's CWE-119
KS = (1, 3, 5)
SUMMARY_PROMPT = ("Describe in one sentence what the code being completed below must do, written like a function "
                  "summary (for example \"Reads a file and returns its lines\"). Do not mention security.\n\n{code}")


def norm(cwe: str) -> str:
    return "CWE-" + str(int(re.sub(r"\D", "", cwe)))  # CWE-022 -> CWE-22


def scenarios(root: Path):
    for info in sorted((root / "data" / "base").glob("*/*/info.json")):
        meta = json.loads(info.read_text())
        d = info.parent
        files = sorted(d.glob("file_context.*")) + sorted(d.glob("func_context.*"))
        yield {"id": f"{meta['cwe']}/{meta['scenario']}", "gold": norm(meta["cwe"]), "language": LANG[meta["language"]],
               "code": "\n".join(f.read_text() for f in files)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("codeguard", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--model", default="gpt-4o-mini")
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    done = {json.loads(l)["id"] for l in args.out.read_text().splitlines()} if args.out.exists() else set()
    driver, embedder, llm = get_driver(), Embedder(), OpenAILLM(args.model)
    retrieve = lambda q, lang, apis: kg_retrieve(driver, embedder, q, lang, apis)  # noqa: E731
    cwes = lambda cands: [c.cwe for c in cands]  # noqa: E731

    with args.out.open("a") as out:
        for n, s in enumerate(scenarios(args.codeguard)):
            if args.limit and n >= args.limit:
                break
            if s["id"] in done:
                continue
            lang, code = s["language"], s["code"]
            summary = llm.chat("You summarize code.", SUMMARY_PROMPT.format(code=code)).strip()
            draft = draft_code(f"Complete this code, returning the full completed function:\n{code}", lang, llm)
            apis = extract_apis(draft, lang)
            comps = split_components(draft, summary, lang, llm, apis)
            rec = dict(s, summary=summary, draft=draft, apis=apis, components=[c.__dict__ for c in comps])
            rec["task"] = cwes(retrieve(summary, lang, [])[1])
            rec["apis_rank"] = cwes(retrieve(summary, lang, apis)[1])
            rec["comps"] = [k.cwe for k in gather_components(comps, lang, retrieve, top_k=max(KS))]
            del rec["code"]
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(s["id"], s["gold"], "task", rec["task"][:3], "apis", rec["apis_rank"][:3], "comps", rec["comps"][:3], flush=True)
    driver.close()


if __name__ == "__main__":
    main()
