"""Functionality retrieval: embed the query, nearest-neighbour search over Functionality nodes, then walk to
the function versions that implement each hit (with CWEs, code, APIs called and FIXES info)."""

from ..common.embed import Embedder
from ..common.graph import Graph
from ..common.lang import compatible_languages
from ..common.models import FixInfo, Hit, Version

# The language filter applies to function versions, after the vector search, so fetch extra
# neighbours and keep the first k that still have a matching version.
OVERFETCH = 5


def search_functionality(
    graph: Graph, embedder: Embedder, query: str, language: str | None = None, k: int = 5
) -> list[Hit]:
    """Top-k Functionality hits (by cosine similarity) that have a version in `language`."""
    langs = compatible_languages(language)
    hits: list[Hit] = []
    for fid, score in graph.nearest(embedder.encode(query), k * OVERFETCH):
        versions = []
        for vid in graph.implementers[fid]:
            props = graph.versions[vid]
            if langs and props.get("language") not in langs:
                continue
            fix = graph.fixes.get(vid)
            versions.append(Version(
                vid, props.get("language"), props["role"], bool(props.get("pair_available", False)),
                list(graph.exhibits[vid]), graph.code_of.get(vid), list(graph.calls[vid]),
                FixInfo(**fix) if fix else None,
            ))
        if versions:
            hits.append(Hit(fid, graph.functionality_text[fid], score, versions))
    return hits[:k]
