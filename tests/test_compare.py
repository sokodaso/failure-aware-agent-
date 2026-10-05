from retrieval.compare import API_WEIGHT, annotate_api_overlap, rank_cwes
from retrieval.lang import compatible_languages
from retrieval.models import FixInfo, Hit, Version


def ver(id, role="vulnerable", cwes=(), apis=(), fix=None):
    return Version(id, "python", role, fix is not None, list(cwes), None, list(apis), fix)


def test_exact_beats_loose_and_missing_scores_zero():
    v = ver("v1", apis=["tarfile.open", "self.os.path.join(a, b)"])
    hit = Hit("f", "t", 0.8, [v])
    annotate_api_overlap([hit], ["tarfile.open", "os.path.join", "open", "shutil.move"])
    # exact + exact + loose('open' ~ tarfile.open) + missing = 2.5 / 4
    assert v.api_overlap == 0.625
    assert v.matched_apis == ["self.os.path.join(a, b)", "tarfile.open"]


def test_cpp_syntax_is_normalised():
    v = ver("v1", apis=["std::memcpy", "serial->type->open"])
    annotate_api_overlap([Hit("f", "t", 0.5, [v])], ["memcpy", "open"])
    assert v.api_overlap == 0.75  # memcpy exact, open loose


def test_no_expected_apis_leaves_overlap_zero():
    v = ver("v1", apis=["open"])
    annotate_api_overlap([Hit("f", "t", 0.5, [v])], [])
    assert v.api_overlap == 0.0 and v.matched_apis == []


def test_rank_uses_similarity_plus_api_bonus_and_excludes_fixed():
    fix = FixInfo("v2", "diff", "cause")
    a = ver("v1", cwes=["CWE-22"], apis=["open"], fix=fix)
    b = ver("v2", role="reported_fixed", cwes=["CWE-22"], fix=fix)
    c = ver("v3", cwes=["CWE-78"])
    hits = [Hit("f1", "t", 0.7, [a, b]), Hit("f2", "t", 0.72, [c])]
    annotate_api_overlap(hits, ["open"])
    ranked = rank_cwes(hits)
    assert [r.cwe for r in ranked] == ["CWE-22", "CWE-78"]  # 0.7 + 0.25 beats 0.72
    assert ranked[0].score == round(0.7 + API_WEIGHT, 4)
    assert [e.version_id for e in ranked[0].evidence] == ["v1"]  # fixed side not evidence
    assert ranked[0].evidence[0].fix.cause == "cause"


def test_rank_truncates_and_orders_evidence():
    vs = [ver(f"v{i}", cwes=["CWE-1"]) for i in range(8)]
    hits = [Hit(f"f{i}", "t", 0.1 * i, [v]) for i, v in enumerate(vs)]
    cand = rank_cwes(hits, top_k=1)[0]
    assert len(cand.evidence) == 5 and cand.evidence[0].version_id == "v7"


def test_language_policy():
    assert compatible_languages("python") == ["python"]
    assert compatible_languages("c") == compatible_languages("CPP") == ["c", "cpp"]
    assert compatible_languages(None) == []
