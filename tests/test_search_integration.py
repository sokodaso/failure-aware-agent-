"""Runs against the live Neo4j graph; skipped when it is unreachable."""

import pytest

from retrieval.db import get_driver
from retrieval.search import Embedder, search_functionality


@pytest.fixture(scope="module")
def driver():
    try:
        d = get_driver()
    except Exception as e:  # unreachable/paused instance, missing .env
        pytest.skip(f"Neo4j unavailable: {e}")
    yield d
    d.close()


@pytest.fixture(scope="module")
def embedder():
    return Embedder()


def test_python_results_are_python_and_sorted(driver, embedder):
    hits = search_functionality(driver, embedder, "extract files from a tar archive into a directory", "python", k=5)
    assert hits and len(hits) <= 5
    sims = [h.similarity for h in hits]
    assert sims == sorted(sims, reverse=True)
    assert all(v.language == "python" for h in hits for v in h.versions)  # py alias is gone


def test_c_query_accepts_cpp_and_roles_are_explicit(driver, embedder):
    hits = search_functionality(driver, embedder, "copy a network packet payload into a fixed size buffer", "c", k=5)
    langs = {v.language for h in hits for v in h.versions}
    assert langs <= {"c", "cpp"}
    assert all(v.role in ("vulnerable", "reported_fixed") for h in hits for v in h.versions)


def test_fix_info_present_only_for_paired_versions(driver, embedder):
    hits = search_functionality(driver, embedder, "extract files from a tar archive into a directory", "python", k=10)
    for h in hits:
        for v in h.versions:
            assert (v.fix is not None) == v.pair_available
