"""python -m harness ISSUE --language python [--file src/x.py] [--out problem.md]

ISSUE is the task text, or @path to read it from a file. Writes the issue plus the failure
analysis as one problem statement for the coding agent, e.g.
  sweagent run --problem_statement.path=problem.md --env.repo.path=./repo ...

Without an OpenAI key, inspect what the model would be shown:
  python -m harness ISSUE --context-only
"""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from retrieval.api import retrieve as kg_retrieve
from retrieval.db import get_driver
from retrieval.search import Embedder

from .analyze import build_context, fmea_prompt
from .knowledge import gather
from .llm import OpenAILLM
from .pipeline import run
from .render import render_insights, render_problem_statement


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("task", help="the issue/task text, or @file; also the functionality query")
    ap.add_argument("--language", default="python")
    ap.add_argument("--api", action="append", default=[], help="expected API call, for the local comparison")
    ap.add_argument("--file", action="append", default=[], help="repository file to show the analysis (repeatable)")
    ap.add_argument("--top-k", type=int, default=3, help="CWEs shown to the analysis")
    ap.add_argument("--out", help="write the full problem statement (issue + analysis) here")
    ap.add_argument("--context-only", action="store_true", help="retrieve and print the first prompt; no LLM")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    task = Path(args.task[1:]).read_text() if args.task.startswith("@") else args.task
    files = {p: Path(p).read_text() for p in args.file}

    driver, embedder = get_driver(), Embedder()
    retrieve = lambda q, lang, apis: kg_retrieve(driver, embedder, q, lang, apis)
    try:
        if args.context_only:
            knowledge = gather(task, args.language, retrieve, args.api, args.top_k)
            print(fmea_prompt(build_context(task, args.language, knowledge, files)))
            return
        analysis = run(task, args.language, OpenAILLM(), retrieve, args.api, args.top_k, files)
    finally:
        driver.close()

    if args.out:
        Path(args.out).write_text(render_problem_statement(task, analysis))
        print(f"wrote {args.out}")
    if args.json:
        print(json.dumps(asdict(analysis), indent=2))
    elif not args.out:
        print(render_insights(analysis))
    for n in analysis.notes:
        print(f"note: {n}")


if __name__ == "__main__":
    main()
