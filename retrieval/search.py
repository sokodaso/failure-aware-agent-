"""Functionality retrieval: embed the query, vector-search Functionality nodes, then walk to
the function versions that implement each hit (with CWEs, code, APIs called and FIXES info)."""

from neo4j import Driver

from kg_pipeline.build_final_graph import EMBEDDING_MODEL_NAME

from .lang import compatible_languages
from .models import FixInfo, Hit, Version

# The language filter applies to function versions, after the vector search, so fetch extra
# neighbours and keep the first k that still have a matching version.
OVERFETCH = 5

_QUERY = """
CALL db.index.vector.queryNodes('functionality_embedding', $n, $embedding)
YIELD node AS f, score
MATCH (v:FunctionVersion)-[:IMPLEMENTS]->(f)
WHERE size($langs) = 0 OR v.language IN $langs
RETURN f.id AS fid, f.text AS ftext, score,
       v.id AS id, v.language AS language, v.role AS role,
       coalesce(v.pair_available, false) AS pair_available,
       [(v)-[:EXHIBITS_WEAKNESS]->(c:CWE) | c.id] AS cwes,
       head([(v)-[:HAS_CODE]->(code:CodeArtifact) | code.code]) AS code,
       [(v)-[:CALLS]->(a:API) | a.text] AS apis,
       head([(v)-[fx:FIXES]-(p:FunctionVersion) |
             {partner_id: p.id, patch: fx.patch, cause: fx.vulnerability_cause}]) AS fix
ORDER BY score DESC
"""


class Embedder:
    """Query-side embedding. Must be the model that embedded the Functionality nodes."""

    def __init__(self, model_name: str = EMBEDDING_MODEL_NAME):
        self.model_name = model_name
        self._model = None

    def encode(self, text: str) -> list[float]:
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
        return [float(x) for x in self._model.encode(text, normalize_embeddings=True)]


def search_functionality(
    driver: Driver, embedder: Embedder, query: str, language: str | None = None, k: int = 5
) -> list[Hit]:
    """Top-k Functionality hits (by cosine similarity) that have a version in `language`."""
    rows = driver.execute_query(
        _QUERY, n=k * OVERFETCH, embedding=embedder.encode(query),
        langs=compatible_languages(language),
    ).records

    hits: dict[str, Hit] = {}
    for r in rows:
        hit = hits.get(r["fid"])
        if hit is None:
            hit = hits[r["fid"]] = Hit(r["fid"], r["ftext"], float(r["score"]), [])
        fix = FixInfo(**r["fix"]) if r["fix"] else None
        hit.versions.append(Version(
            r["id"], r["language"], r["role"], r["pair_available"], r["cwes"], r["code"],
            r["apis"], fix,
        ))
    return sorted(hits.values(), key=lambda h: -h.similarity)[:k]
