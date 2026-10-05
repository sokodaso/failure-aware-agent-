"""Attach CWE descriptions, mitigating guidelines and CAPEC attack patterns to candidates."""

from neo4j import Driver

from .models import CweCandidate

_QUERY = """
MATCH (c:CWE) WHERE c.id IN $ids
RETURN c.id AS id, c.name AS name, c.summary AS summary,
       [(g:SecurityGuideline)-[:MITIGATES]->(c) | g.text] AS guidelines,
       [(ap:AttackPattern)-[:EXPLOITS_WEAKNESS]->(c) | ap.name] AS patterns
"""


def attach_cwe_context(driver: Driver, candidates: list[CweCandidate]) -> None:
    rows = {r["id"]: r for r in driver.execute_query(_QUERY, ids=[c.cwe for c in candidates]).records}
    for c in candidates:
        r = rows.get(c.cwe)
        if r:
            c.name, c.summary = r["name"] or "", r["summary"] or ""
            c.guidelines, c.attack_patterns = r["guidelines"], r["patterns"]
