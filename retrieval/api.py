"""The retrieval entry point other packages call."""

from .compare import annotate_api_overlap, rank_cwes
from .context import attach_cwe_context
from .models import CweCandidate, Hit
from .search import search_functionality


def retrieve(
    driver, embedder, query: str, language: str | None = None, expected_apis=(), k: int = 5, top_cwes: int = 5
) -> tuple[list[Hit], list[CweCandidate]]:
    """Functionality search -> local API comparison -> ranked CWEs with context."""
    hits = search_functionality(driver, embedder, query, language, k)
    annotate_api_overlap(hits, list(expected_apis))
    candidates = rank_cwes(hits, top_cwes)
    attach_cwe_context(driver, candidates)
    return hits, candidates
