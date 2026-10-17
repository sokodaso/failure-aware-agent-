"""fagent retrieval: functionality search -> local API comparison -> ranked CWEs with context."""

from ..common.base import Probe, Retrieval
from ..common.embed import Embedder
from ..common.graph import Graph
from ..common.models import CweCandidate, Hit
from .compare import annotate_api_overlap, rank_cwes
from .context import attach_cwe_context
from .search import search_functionality


def retrieve(
    graph: Graph, embedder: Embedder, query: str, language: str | None = None, expected_apis=(), k: int = 5,
    top_cwes: int = 5,
) -> tuple[list[Hit], list[CweCandidate]]:
    hits = search_functionality(graph, embedder, query, language, k)
    annotate_api_overlap(hits, list(expected_apis))
    candidates = rank_cwes(hits, top_cwes)
    attach_cwe_context(graph, candidates)
    return hits, candidates


class FagentRetriever:
    """One query: the probe's summary (the task text when there is none). The probe's APIs only count as expected
    APIs, a bonus on top of functionality similarity, when `use_apis` is set."""

    def __init__(self, graph: Graph, embedder: Embedder | None = None, *, use_apis: bool = False, k: int = 5,
                 top_cwes: int = 5):
        self.graph, self.embedder = graph, embedder or Embedder(graph.embedding_model)
        self.use_apis, self.k, self.top_cwes = use_apis, k, top_cwes

    def retrieve(self, probe: Probe) -> Retrieval:
        apis = probe.apis if self.use_apis else []
        hits, candidates = retrieve(self.graph, self.embedder, probe.summary or probe.task, probe.language, apis,
                                    self.k, self.top_cwes)
        return Retrieval(candidates, {"hits": hits, "apis_used": apis})
