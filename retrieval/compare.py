"""Compare expected API calls against the functions functionality retrieval already returned,
then rank the CWEs they exhibit.

API names in the graph are raw call-site spellings (receiver variable names, embedded args,
`::`/`->` syntax), so they are unusable as a global index. Here the candidate set is small, so
a forgiving match is safe:
  exact  (EXACT_MATCH)  same name after dropping call args, a leading `self.` and `std::`/`::`
  loose  (LOOSE_MATCH)  same last segment only (`tarfile.open` ~ `open`)

Scoring:
  version score = similarity + API_WEIGHT * api_overlap     (similarity alone if no APIs given)
  CWE score     = best score among its weakness-exhibiting versions
API overlap is a bonus on top of functionality similarity, never a gate.
"""

import re
from collections import defaultdict

from .models import CweCandidate, Evidence, Hit, Version

EXACT_MATCH = 1.0
LOOSE_MATCH = 0.5
API_WEIGHT = 0.25
MAX_EVIDENCE_PER_CWE = 5


def _full(name: str) -> str:
    s = name.strip().split("(", 1)[0].strip()
    for prefix in ("self.", "std::", "::"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s


def _last(name: str) -> str:
    return re.split(r"->|::|\.", _full(name))[-1]


def annotate_api_overlap(hits: list[Hit], expected_apis: list[str]) -> None:
    """Set api_overlap / matched_apis on every version, in place."""
    if not expected_apis:
        return
    for hit in hits:
        for v in hit.versions:
            fulls = {_full(a): a for a in v.apis}
            lasts = {_last(a): a for a in v.apis}
            total, matched = 0.0, set()
            for e in expected_apis:
                if _full(e) in fulls:
                    total += EXACT_MATCH
                    matched.add(fulls[_full(e)])
                elif _last(e) in lasts:
                    total += LOOSE_MATCH
                    matched.add(lasts[_last(e)])
            v.api_overlap = round(total / len(expected_apis), 4)
            v.matched_apis = sorted(matched)


def version_score(similarity: float, v: Version) -> float:
    return round(similarity + API_WEIGHT * v.api_overlap, 4)


def rank_cwes(hits: list[Hit], top_k: int = 5) -> list[CweCandidate]:
    """CWEs exhibited by the retrieved weakness-exhibiting versions, best evidence first.

    reported_fixed versions are excluded as evidence of a weakness; they surface through the
    FIXES info carried on the vulnerable side of each pair.
    """
    by_cwe: dict[str, list[Evidence]] = defaultdict(list)
    for hit in hits:
        for v in hit.versions:
            if v.role == "reported_fixed":
                continue
            ev = Evidence(v.id, version_score(hit.similarity, v), hit.similarity, v.api_overlap, v.fix)
            for cwe in v.cwes:
                by_cwe[cwe].append(ev)

    candidates = []
    for cwe, evidence in by_cwe.items():
        evidence.sort(key=lambda e: -e.score)
        candidates.append(CweCandidate(cwe, evidence[0].score, evidence[:MAX_EVIDENCE_PER_CWE]))
    candidates.sort(key=lambda c: -c.score)
    return candidates[:top_k]
