import json

from harness.analyze import MAX_NODES, MAX_PATCH, build_context, parse_json, prune_tree
from harness.knowledge import gather
from harness.pipeline import run
from harness.render import render_problem_statement
from retrieval.models import CweCandidate, Evidence, FixInfo


def cand(cwe, score, cause=None, patch="x" * 5000):
    fix = FixInfo("v2", patch, cause) if cause else None
    return CweCandidate(cwe, score, [Evidence("v1", score, score, 0.0, fix)], name=f"name {cwe}",
                        guidelines=[f"guideline {cwe}"])


def make_retrieve(log):
    def retrieve(query, language, apis):
        log.append((query, language, apis))
        return [], [cand("CWE-22", 0.8, "no path check"), cand("CWE-78", 0.5), cand("CWE-89", 0.4)]
    return retrieve


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


def test_task_text_is_the_retrieval_query_and_top_k_applies():
    log = []
    ks = gather("extract uploads", "python", make_retrieve(log), ["tarfile.open"], top_k=2)
    assert log == [("extract uploads", "python", ["tarfile.open"])]
    assert [k.cwe for k in ks] == ["CWE-22", "CWE-78"]


def test_context_clips_patches_and_states_empty_knowledge():
    ks = gather("t", "python", make_retrieve([]))
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
    a = run("extract uploaded archives", "python", llm, make_retrieve([]), top_k=2)
    assert [f.id for f in a.failure_modes][:2] == ["FM7", "FM2"] and a.failure_modes[0].rpn == 25
    assert [t.failure_mode_id for t in a.fault_trees] == ["FM7"]
    assert [x.failure_ids for x in a.actions] == [["FM7"]]
    assert "FM6" in " ".join(a.notes) and "FM99" not in [i for x in a.actions for i in x.failure_ids]
    assert "FM6" not in llm.prompts[1][1].split("Highest-RPN")[1].split("Return:")[0]  # FTA saw only the top 5


def test_history_claim_without_retrieved_cwe_is_downgraded():
    bad = fm(1, 3, 3, level="history", ref="CWE-999", cwe="CWE-999")
    llm = ScriptedLLM(json.dumps({"failure_modes": [bad]}), json.dumps({"fault_trees": [], "actions": []}))
    a = run("t", "python", llm, make_retrieve([]))
    assert a.failure_modes[0].evidence[0].level == "inference"
    assert any("downgraded" in n for n in a.notes)


def test_invalid_json_is_retried_once():
    llm = ScriptedLLM("not json", json.dumps({"failure_modes": []}))
    assert run("t", "python", llm, make_retrieve([])).failure_modes == []
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
    a = run("t", "python", ScriptedLLM(json.dumps(fmea), json.dumps(fta)), make_retrieve([]))
    text = render_problem_statement("Fix the extractor", a)
    assert text.startswith("Fix the extractor") and "not established facts" in text and "RPN 16" in text
