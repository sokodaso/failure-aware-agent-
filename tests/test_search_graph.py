"""Search over the real data/final_kg/graph.json (needs the cached sentence-transformer model)."""

import pytest

from retrieval.graph import load_graph
from retrieval.search import Embedder, search_functionality


@pytest.fixture(scope="module")
def graph():
    return load_graph()


@pytest.fixture(scope="module")
def embedder():
    return Embedder()


def test_python_results_are_python_and_sorted(graph, embedder):
    hits = search_functionality(graph, embedder, "extract files from a tar archive into a directory", "python", k=5)
    assert hits and len(hits) <= 5
    sims = [h.similarity for h in hits]
    assert sims == sorted(sims, reverse=True)
    assert all(v.language == "python" for h in hits for v in h.versions)  # py alias is gone


def test_c_query_accepts_cpp_and_roles_are_explicit(graph, embedder):
    hits = search_functionality(graph, embedder, "copy a network packet payload into a fixed size buffer", "c", k=5)
    langs = {v.language for h in hits for v in h.versions}
    assert langs <= {"c", "cpp"}
    assert all(v.role in ("vulnerable", "reported_fixed") for h in hits for v in h.versions)


def test_fix_info_present_only_for_paired_versions(graph, embedder):
    hits = search_functionality(graph, embedder, "extract files from a tar archive into a directory", "python", k=10)
    for h in hits:
        for v in h.versions:
            assert (v.fix is not None) == v.pair_available
