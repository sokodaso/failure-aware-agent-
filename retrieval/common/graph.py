"""The knowledge graph, read straight from data/final_kg/graph.json (no database).

Everything retrieval needs is indexed once at load time: the Functionality embedding matrix, the
functionality -> function version walk (language, role, CWEs, code, APIs called, FIXES info) and the
per-CWE context (guidelines, attack patterns). The graph is read-only, so one instance can be shared
across threads.
"""

import json
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import numpy as np

GRAPH_PATH = Path(__file__).parent.parent.parent / "data" / "final_kg" / "graph.json"


class Graph:
    def __init__(self, data: dict):
        self.embedding_model: str = data["embedding_model"]
        nodes: dict[str, dict[str, dict]] = defaultdict(dict)
        for n in data["nodes"]:
            nodes[n["label"]][n["id"]] = n["props"]

        self.cwes: dict[str, dict] = nodes["CWE"]
        self.versions: dict[str, dict] = nodes["FunctionVersion"]
        self._code = {i: p["code"] for i, p in nodes["CodeArtifact"].items()}
        self._api = {i: p["text"] for i, p in nodes["API"].items()}
        self._guideline = {i: p["text"] for i, p in nodes["SecurityGuideline"].items()}
        self._pattern = {i: p["name"] for i, p in nodes["AttackPattern"].items()}

        self.functionality_ids = list(nodes["Functionality"])
        self.functionality_text = {i: p["text"] for i, p in nodes["Functionality"].items()}
        self.embeddings = np.array([nodes["Functionality"][i]["embedding"] for i in self.functionality_ids],
                                   dtype=np.float32)
        self.embeddings /= np.linalg.norm(self.embeddings, axis=1, keepdims=True)

        self.implementers: dict[str, list[str]] = defaultdict(list)  # functionality id -> version ids
        self.exhibits: dict[str, list[str]] = defaultdict(list)  # version id -> CWE ids
        self.code_of: dict[str, str] = {}  # version id -> code
        self.calls: dict[str, list[str]] = defaultdict(list)  # version id -> API spellings
        self.fixes: dict[str, dict] = {}  # version id -> {partner_id, patch, cause}, either side of the pair
        self.guidelines: dict[str, list[str]] = defaultdict(list)  # CWE id -> guideline texts
        self.patterns: dict[str, list[str]] = defaultdict(list)  # CWE id -> CAPEC pattern names
        for r in data["relationships"]:
            t, s, d = r["type"], r["source"], r["target"]
            if t == "IMPLEMENTS":
                self.implementers[d].append(s)
            elif t == "EXHIBITS_WEAKNESS":
                self.exhibits[s].append(d)
            elif t == "HAS_CODE":
                self.code_of[s] = self._code[d]
            elif t == "CALLS":
                self.calls[s].append(self._api[d])
            elif t == "MITIGATES":
                self.guidelines[d].append(self._guideline[s])
            elif t == "EXPLOITS_WEAKNESS":
                self.patterns[d].append(self._pattern[s])
            elif t == "FIXES":  # fixed -> vulnerable; both ends carry the pair's info
                p = r["props"]
                self.fixes.setdefault(s, {"partner_id": d, "patch": p.get("patch"), "cause": p.get("vulnerability_cause")})
                self.fixes.setdefault(d, {"partner_id": s, "patch": p.get("patch"), "cause": p.get("vulnerability_cause")})

    def nearest(self, query_embedding: list[float], n: int) -> list[tuple[str, float]]:
        """The n Functionality nodes closest to the query, as (id, score). The score is (1 + cosine) / 2,
        the scale Neo4j's cosine vector index reports, so API-overlap bonuses keep the same relative weight."""
        sims = (1.0 + self.embeddings @ np.asarray(query_embedding, dtype=np.float32)) / 2.0
        top = np.argsort(-sims, kind="stable")[:n]
        return [(self.functionality_ids[i], float(sims[i])) for i in top]


@lru_cache(maxsize=1)
def load_graph(path: Path = GRAPH_PATH) -> Graph:
    return Graph(json.loads(Path(path).read_text()))
