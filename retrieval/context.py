"""Attach CWE descriptions, mitigating guidelines and CAPEC attack patterns to candidates."""

from .graph import Graph
from .models import CweCandidate


def attach_cwe_context(graph: Graph, candidates: list[CweCandidate]) -> None:
    for c in candidates:
        props = graph.cwes.get(c.cwe)
        if props:
            c.name, c.summary = props.get("name") or "", props.get("summary") or ""
            c.guidelines, c.attack_patterns = list(graph.guidelines[c.cwe]), list(graph.patterns[c.cwe])
