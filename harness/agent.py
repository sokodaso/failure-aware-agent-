"""Run mini-swe-agent on a task, optionally preceded by the failure analysis.

python -m harness.agent TASK --language python --workdir ./work [--model MODEL] [--no-harness]

With the harness: task -> retrieval -> FMEA/FTA -> problem statement -> mini-swe-agent.
With --no-harness the agent gets the raw task, so baseline and treatment share one code path.
"""

import argparse
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

os.environ.setdefault("MSWEA_SILENT_STARTUP", "1")  # no banner on import

import yaml  # noqa: E402
from minisweagent import package_dir  # noqa: E402
from minisweagent.agents.default import DefaultAgent  # noqa: E402
from minisweagent.environments.local import LocalEnvironment  # noqa: E402
from minisweagent.models.litellm_model import LitellmModel  # noqa: E402

from .llm import LLM  # noqa: E402
from .models import Analysis  # noqa: E402
from .sandbox import SandboxedLocalEnvironment  # noqa: E402
from .pipeline import run  # noqa: E402
from .render import render_problem_statement  # noqa: E402

DEFAULT_CONFIG = package_dir / "config" / "mini.yaml"
PROMPT_CONFIG = Path(__file__).parent / "agent_prompt.yaml"  # generation-task framing over mini's defaults


@dataclass
class SolveResult:
    problem_statement: str
    exit_status: str
    submission: str
    cost: float
    n_calls: int
    analysis: Analysis | None = None
    notes: list[str] = field(default_factory=list)


def solve(task: str, language: str = "python", *, workdir: str | Path, model=None, model_name: str | None = None,
          harness: bool = True, llm: LLM | None = None, retrieve=None, apis: list[str] | None = None,
          top_k: int = 3, files: dict[str, str] | None = None, step_limit: int = 0, cost_limit: float = 3.0,
          trajectory: Path | None = None, problem_out: Path | None = None, sandbox: bool = True,
          config_path: Path = DEFAULT_CONFIG) -> SolveResult:
    """Run the agent in `workdir`. `model` (a mini-swe-agent Model) overrides `model_name`, e.g. for tests."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    problem, analysis = task, None
    if harness:
        if llm is None or retrieve is None:
            raise ValueError("harness=True needs llm and retrieve")
        analysis = run(task, language, llm, retrieve, apis, top_k, files)
        problem = render_problem_statement(task, analysis)
    if problem_out:
        problem_out.write_text(problem)

    cfg = yaml.safe_load(Path(config_path).read_text())
    agent_cfg = {k: v for k, v in cfg["agent"].items() if k != "mode"}  # `mode` belongs to the interactive UI
    agent_cfg |= yaml.safe_load(PROMPT_CONFIG.read_text())["agent"]
    agent_cfg |= {"step_limit": step_limit, "cost_limit": cost_limit, "output_path": trajectory}
    if model is None:
        model = LitellmModel(model_name=model_name or os.environ["MSWEA_MODEL_NAME"], **cfg.get("model", {}))
    env_class = SandboxedLocalEnvironment if sandbox else LocalEnvironment
    env = env_class(cwd=str(workdir), **cfg.get("environment", {}))

    agent = DefaultAgent(model, env, **agent_cfg)
    out = agent.run(problem)
    return SolveResult(problem, out.get("exit_status", ""), out.get("submission", ""), agent.cost, agent.n_calls,
                       analysis, analysis.notes if analysis else [])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("task", help="the task text, or @file")
    ap.add_argument("--language", default="python")
    ap.add_argument("--workdir", required=True, help="directory the agent works in")
    ap.add_argument("--model", help="litellm model name (default: $MSWEA_MODEL_NAME)")
    ap.add_argument("--no-harness", action="store_true", help="baseline: skip retrieval and failure analysis")
    ap.add_argument("--api", action="append", default=[], help="expected API call, for the local comparison")
    ap.add_argument("--top-k", type=int, default=3)
    ap.add_argument("--step-limit", type=int, default=0)
    ap.add_argument("--cost-limit", type=float, default=3.0)
    ap.add_argument("--trajectory", type=Path, help="save the agent trajectory (json) here")
    ap.add_argument("--no-sandbox", action="store_true", help="run commands unsandboxed (not recommended)")
    ap.add_argument("--problem-out", type=Path, help="save the problem statement the agent saw")
    args = ap.parse_args()

    task = Path(args.task[1:]).read_text() if args.task.startswith("@") else args.task
    llm = retrieve = driver = None
    if not args.no_harness:
        from retrieval.api import retrieve as kg_retrieve
        from retrieval.db import get_driver
        from retrieval.search import Embedder

        from .llm import OpenAILLM

        driver, embedder = get_driver(), Embedder()
        retrieve = lambda q, lang, apis: kg_retrieve(driver, embedder, q, lang, apis)  # noqa: E731
        llm = OpenAILLM()
    try:
        res = solve(task, args.language, workdir=args.workdir, model_name=args.model, harness=not args.no_harness,
                    llm=llm, retrieve=retrieve, apis=args.api, top_k=args.top_k, step_limit=args.step_limit,
                    cost_limit=args.cost_limit, trajectory=args.trajectory, problem_out=args.problem_out,
                    sandbox=not args.no_sandbox)
    finally:
        if driver:
            driver.close()

    print(json.dumps({"exit_status": res.exit_status, "cost": res.cost, "n_calls": res.n_calls,
                      "submission": res.submission, "notes": res.notes}, indent=2))


if __name__ == "__main__":
    main()
