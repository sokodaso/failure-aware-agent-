import json

from harness.analyze import MAX_NODES, MAX_PATCH, build_context, parse_json, prune_tree
from harness.knowledge import gather
from harness.pipeline import run
from harness.render import render_problem_statement
from retrieval.common.base import Probe, Retrieval
from retrieval.common.models import CweCandidate, Evidence, FixInfo


def cand(cwe, score, cause=None, patch="x" * 5000):
    fix = FixInfo("v2", patch, cause) if cause else None
    return CweCandidate(cwe, score, [Evidence("v1", score, score, 0.0, fix)], name=f"name {cwe}",
                        guidelines=[f"guideline {cwe}"])


class FakeRetriever:
    def __init__(self, log):
        self.log = log

    def retrieve(self, probe):
        self.log.append(probe)
        return Retrieval([cand("CWE-22", 0.8, "no path check"), cand("CWE-78", 0.5), cand("CWE-89", 0.4)])


def make_retriever(log):
    return FakeRetriever(log)


def fm(i, sev, lik, level="history", ref="CWE-22", cwe="CWE-22"):
    return {"id": f"FM{i}", "component": "extract()", "failure_mode": f"mode {i}", "viewpoint": "security",
            "effect": "writes outside dest", "severity": sev, "likelihood": lik, "cwe": cwe,
            "evidence": [{"level": level, "ref": ref}], "control": "resolve and check prefix"}


class ScriptedLLM:
    """Returns the next canned reply per call; records prompts."""
    def __init__(self, *replies):
        self.replies, self.prompts = list(replies), []

    def chat(self, system, user):
        self.prompts.append((system, user))
        return self.replies.pop(0)


def test_probe_goes_to_the_retriever_and_top_k_applies():
    log = []
    probe = Probe("extract uploads", "python", apis=["tarfile.open"])
    ks = gather(make_retriever(log), probe, top_k=2)
    assert log == [probe]
    assert [k.cwe for k in ks] == ["CWE-22", "CWE-78"]


def test_context_clips_patches_and_states_empty_knowledge():
    ks = gather(make_retriever([]), Probe("t", "python"))
    ctx = build_context("extract uploads", "python", ks)
    assert "no path check" in ctx and "[truncated]" in ctx and ctx.count("x") <= MAX_PATCH + 50
    assert "no relevant historical failures" in build_context("t", "python", [])


def test_parse_json_fenced_and_bare():
    assert parse_json('ok\n```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json('Sure: {"a": 1}') == {"a": 1}


def test_pipeline_ranks_by_rpn_computes_it_and_limits_fta():
    fmea = {"failure_modes": [fm(1, 2, 2), fm(2, 5, 4), fm(3, 4, 4), fm(4, 3, 3), fm(5, 3, 2), fm(6, 1, 1), fm(7, 5, 5)]}
    fta = {"fault_trees": [
        {"failure_mode_id": "FM7", "top_event": "escape", "root": {"event": "escape", "gate": "OR", "cause_type": "value",
         "children": [{"event": "no check"}, {"event": "symlink"}]}},
        {"failure_mode_id": "FM6", "top_event": "low", "root": {"event": "low"}},  # not top 5
    ], "actions": [
        {"action": "resolve member paths", "targets": ["extract"], "failure_ids": ["FM7"], "verification": "test ../x"},
        {"action": "ghost", "failure_ids": ["FM99"]},
    ]}
    llm = ScriptedLLM(json.dumps(fmea), json.dumps(fta))
    a = run("extract uploaded archives", "python", llm, make_retriever([]), top_k=2)
    assert [f.id for f in a.failure_modes][:2] == ["FM7", "FM2"] and a.failure_modes[0].rpn == 25
    assert [t.failure_mode_id for t in a.fault_trees] == ["FM7"]
    assert [x.failure_ids for x in a.actions] == [["FM7"]]
    assert "FM6" in " ".join(a.notes) and "FM99" not in [i for x in a.actions for i in x.failure_ids]
    assert "FM6" not in llm.prompts[1][1].split("Highest-RPN")[1].split("Return:")[0]  # FTA saw only the top 5


def test_history_claim_without_retrieved_cwe_is_downgraded():
    bad = fm(1, 3, 3, level="history", ref="CWE-999", cwe="CWE-999")
    llm = ScriptedLLM(json.dumps({"failure_modes": [bad]}), json.dumps({"fault_trees": [], "actions": []}))
    a = run("t", "python", llm, make_retriever([]))
    assert a.failure_modes[0].evidence[0].level == "inference"
    assert any("downgraded" in n for n in a.notes)


def test_invalid_json_is_retried_once():
    llm = ScriptedLLM("not json", json.dumps({"failure_modes": []}))
    assert run("t", "python", llm, make_retriever([])).failure_modes == []
    assert "not valid JSON" in llm.prompts[1][1]


def test_prune_tree_enforces_limits():
    deep = {"event": "e", "gate": "OR", "children": [{"event": f"c{i}", "gate": "AND", "children": [
        {"event": f"g{i}{j}", "children": [{"event": "too deep", "children": [{"event": "way too deep"}]}]}
        for j in range(4)]} for i in range(4)]}
    root, count, depth = prune_tree(deep), 0, 0

    def walk(n, d):
        nonlocal count, depth
        count, depth = count + 1, max(depth, d)
        for c in n.children:
            walk(c, d + 1)
    walk(root, 1)
    assert count <= MAX_NODES and depth <= 3


def test_problem_statement_keeps_issue_and_marks_hypotheses():
    fmea = {"failure_modes": [fm(1, 4, 4)]}
    fta = {"fault_trees": [], "actions": [{"action": "validate paths", "failure_ids": ["FM1"], "verification": "t"}]}
    a = run("t", "python", ScriptedLLM(json.dumps(fmea), json.dumps(fta)), make_retriever([]))
    text = render_problem_statement("Fix the extractor", a)
    assert text.startswith("Fix the extractor") and "not established facts" in text and "RPN 16" in text


# ---- v2: draft first, APIs drive retrieval, analysis attacks the draft
from harness.agent import solve  # noqa: E402
from harness.draft import draft_code, extract_apis  # noqa: E402
from harness.pipeline import run_v2  # noqa: E402


def test_extract_apis_python_dedups_and_skips_noise():
    code = "import tarfile\ndef f(p, d):\n    with tarfile.open(p) as t:\n        t.extractall(d)\n    print(len(p)); tarfile.open(p)"
    assert extract_apis(code, "python") == ["tarfile.open", "t.extractall"]


def test_extract_apis_c_and_unparsable_python_fall_back_to_regex():
    assert extract_apis("int f(){ if (x) { strcpy(a, b); } return s->read(1); }", "c") == ["f", "strcpy", "s->read"]
    assert "os.system" in extract_apis("def f(:\n  os.system(x)", "python")


def test_draft_code_takes_the_fenced_block():
    assert draft_code("t", "python", ScriptedLLM("here:\n```python\nx = 1\n```\nbye")) == "x = 1"


def test_v2_drafts_first_retrieves_by_task_only_and_analyzes_the_draft():
    log = []
    fmea = {"failure_modes": [fm(1, 4, 4)], "retrieval_fit": [{"cwe": "CWE-22", "applies": False, "reason": "basename"}]}
    llm = ScriptedLLM("```python\nimport os\nos.remove(p)\n```", json.dumps(fmea),
                      json.dumps({"fault_trees": [], "actions": []}))
    a, draft = run_v2("delete a file", "python", llm, make_retriever(log))
    assert draft == "import os\nos.remove(p)"
    assert log == [Probe("delete a file", "python", draft=draft, apis=["os.remove"])]
    assert "Draft implementation" in llm.prompts[1][1] and "os.remove" in llm.prompts[1][1]
    assert "APIs called by the draft: os.remove" in llm.prompts[1][1]
    assert "retrieval_fit" in llm.prompts[1][1] and "has NOT yet" not in llm.prompts[1][0]
    assert any("does not fit" in n for n in a.notes)
    text = render_problem_statement("delete a file", a, draft)
    assert "## Draft implementation" in text and "os.remove(p)" in text and "Retrieval notes" in text


def test_v1_prompt_is_unchanged_by_v2():
    llm = ScriptedLLM(json.dumps({"failure_modes": []}))
    run("t", "python", llm, make_retriever([]))
    assert "has NOT yet" in llm.prompts[0][0] and "Draft implementation" not in llm.prompts[0][1]


def test_v1_and_v2_share_the_rules_and_differ_only_in_component_wording():
    from harness.analyze import COMPONENT_V1, COMPONENT_V2, FMEA_RULES, fmea_prompt
    p1, p2 = fmea_prompt("ctx"), fmea_prompt("ctx", v2=True)
    for p in (p1, p2):
        assert FMEA_RULES in p and "valid_check" in p and "retrieval_fit" in p and "CANDIDATES" in p
    assert COMPONENT_V1 in p1 and COMPONENT_V2 in p2 and COMPONENT_V2 not in p1
    assert p1.replace(COMPONENT_V1, "") == p2.replace(COMPONENT_V2, "")


def test_fta_prompt_requires_attack_and_happy_path_checks():
    from harness.analyze import fta_prompt
    from harness.models import FailureMode
    p = fta_prompt("ctx", [FailureMode("FM1", "c", "m", "security", "e", 3, 3)])
    assert "attack" in p and "happy-path" in p


def test_v1_retrieval_fit_notes_and_valid_check_reach_the_problem_statement():
    f = dict(fm(1, 4, 4), valid_check="a/b.txt inside dest")
    fmea = {"failure_modes": [f], "retrieval_fit": [{"cwe": "CWE-78", "applies": False, "reason": "no shell"}]}
    a = run("t", "python", ScriptedLLM(json.dumps(fmea), json.dumps({"fault_trees": [], "actions": []})), make_retriever([]))
    assert a.failure_modes[0].valid_check == "a/b.txt inside dest"
    text = render_problem_statement("t", a)
    assert "Control: resolve and check prefix" in text and "Must still accept: a/b.txt inside dest" in text
    assert "Retrieval notes" in text and "CWE-78" in text

