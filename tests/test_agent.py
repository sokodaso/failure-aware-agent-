import json
import sys
from pathlib import Path

import pytest
from minisweagent.models.test_models import DeterministicModel, make_output

from harness.agent import solve
from tests.test_harness import ScriptedLLM, fm, make_retrieve


def script():
    return DeterministicModel(outputs=[
        make_output("write", [{"command": "echo hi > out.txt"}]),
        make_output("submit", [{"command": "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\ncat out.txt"}]),
    ])


def test_baseline_gives_agent_the_raw_task(tmp_path):
    res = solve("write hi", workdir=tmp_path / "w", model=script(), harness=False, problem_out=tmp_path / "p.md")
    assert res.exit_status == "Submitted" and res.submission == "hi\n" and res.analysis is None
    assert (tmp_path / "w" / "out.txt").read_text() == "hi\n"
    assert (tmp_path / "p.md").read_text() == "write hi"


def test_harness_prepends_analysis_to_the_problem(tmp_path):
    llm = ScriptedLLM(json.dumps({"failure_modes": [fm(1, 5, 5)]}), json.dumps({"fault_trees": [], "actions": []}))
    res = solve("write hi", workdir=tmp_path, model=script(), harness=True, llm=llm, retrieve=make_retrieve([]))
    assert res.problem_statement.startswith("write hi") and len(res.problem_statement) > len("write hi")
    assert res.analysis is not None and res.exit_status == "Submitted"


def test_harness_requires_llm_and_retrieve(tmp_path):
    with pytest.raises(ValueError):
        solve("t", workdir=tmp_path, model=script(), harness=True)


@pytest.mark.skipif(sys.platform != "darwin", reason="sandbox-exec is macOS only")
def test_sandbox_confines_writes_reads_and_network(tmp_path):
    from harness.sandbox import SandboxedLocalEnvironment

    outside = Path.home() / "sandbox_escape_probe.txt"
    env = SandboxedLocalEnvironment(cwd=str(tmp_path / "w"))
    assert env.execute({"command": "echo ok > in.txt && cat in.txt"})["output"] == "ok\n"
    assert env.execute({"command": f"echo x > {outside}"})["returncode"] != 0 and not outside.exists()
    assert env.execute({"command": "cd .. && ls ~/.. /Users"})["returncode"] != 0
    assert env.execute({"command": "curl -s -m 3 http://example.com"})["returncode"] != 0
