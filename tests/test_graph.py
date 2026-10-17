import math

from retrieval.common.base import Probe
from retrieval.common.graph import Graph
from retrieval.fagent.retriever import FagentRetriever, retrieve


def node(label, id, **props):
    return {"label": label, "id": id, "props": props}


def rel(type, source, target, **props):
    return {"type": type, "source": source, "target": target, "props": props}


def unit(x, y):
    n = math.hypot(x, y)
    return [x / n, y / n]


class FakeEmbedder:
    def encode(self, text):
        return unit(1, 0)


def tiny() -> Graph:
    nodes = [
        node("CWE", "CWE-22", name="Path Traversal", summary="s"),
        node("SecurityGuideline", "g1", text="validate paths"),
        node("AttackPattern", "ap1", name="Path Traversal"),
        node("Functionality", "f1", text="extract a tar archive", embedding=[1.0, 0.0]),
        node("Functionality", "f2", text="render a page", embedding=[0.0, 1.0]),
        node("FunctionVersion", "v_vul", language="python", role="vulnerable", pair_available=True),
        node("FunctionVersion", "v_fix", language="python", role="reported_fixed", pair_available=True),
        node("FunctionVersion", "v_c", language="cpp", role="vulnerable"),
        node("CodeArtifact", "code1", code="def f(): pass"),
        node("API", "a1", text="tarfile.open"),
    ]
    rels = [
        rel("IMPLEMENTS", "v_vul", "f1"), rel("IMPLEMENTS", "v_fix", "f1"), rel("IMPLEMENTS", "v_c", "f2"),
        rel("EXHIBITS_WEAKNESS", "v_vul", "CWE-22"), rel("HAS_CODE", "v_vul", "code1"), rel("CALLS", "v_vul", "a1"),
        rel("FIXES", "v_fix", "v_vul", patch="--- p", vulnerability_cause="no path check"),
        rel("MITIGATES", "g1", "CWE-22"), rel("EXPLOITS_WEAKNESS", "ap1", "CWE-22"),
    ]
    return Graph({"embedding_model": "m", "nodes": nodes, "relationships": rels})


def test_nearest_uses_the_neo4j_score_scale():
    g = tiny()
    (fid, score), (fid2, score2) = g.nearest(unit(1, 0), 2)
    assert (fid, fid2) == ("f1", "f2")
    assert score == 1.0 and score2 == 0.5  # cosine 1 -> 1.0, cosine 0 -> 0.5


def test_fixes_info_is_on_both_ends_of_the_pair():
    g = tiny()
    assert g.fixes["v_vul"] == {"partner_id": "v_fix", "patch": "--- p", "cause": "no path check"}
    assert g.fixes["v_fix"]["partner_id"] == "v_vul"


def test_retrieve_walks_versions_and_attaches_context():
    hits, cands = retrieve(tiny(), FakeEmbedder(), "x", "python", k=2)
    assert [h.functionality_id for h in hits] == ["f1"]  # f2 only has a cpp version
    vul = next(v for v in hits[0].versions if v.role == "vulnerable")
    assert (vul.cwes, vul.code, vul.apis, vul.pair_available) == (["CWE-22"], "def f(): pass", ["tarfile.open"], True)
    assert vul.fix.cause == "no path check"
    assert [c.cwe for c in cands] == ["CWE-22"]  # the reported_fixed version is not evidence
    assert cands[0].guidelines == ["validate paths"] and cands[0].attack_patterns == ["Path Traversal"]
    assert cands[0].name == "Path Traversal"


def test_fagent_retriever_queries_with_the_summary_and_uses_apis_only_when_asked():
    class Spy(FakeEmbedder):
        def __init__(self):
            self.queries = []

        def encode(self, text):
            self.queries.append(text)
            return super().encode(text)

    spy = Spy()
    probe = Probe("long task text", "python", summary="extract a tar archive", draft="d", apis=["tarfile.open"])
    off = FagentRetriever(tiny(), spy).retrieve(probe)
    on = FagentRetriever(tiny(), spy, use_apis=True).retrieve(probe)
    assert spy.queries == ["extract a tar archive"] * 2
    assert off.trace["apis_used"] == [] and on.trace["apis_used"] == ["tarfile.open"]
    assert on.candidates[0].score > off.candidates[0].score  # API overlap is a bonus on top of similarity
    assert FagentRetriever(tiny(), spy).retrieve(Probe("only the task", "python")) and spy.queries[-1] == "only the task"
