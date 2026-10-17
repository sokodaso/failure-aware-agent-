"""Task -> retrieval -> the knowledge the generator is shown."""

from retrieval.common.base import Probe, Retriever
from retrieval.common.models import CweCandidate

from .models import Knowledge


def to_knowledge(candidates: list[CweCandidate]) -> list[Knowledge]:
    out = []
    for c in candidates:
        fix = next((e.fix for e in c.evidence if e.fix), None)
        out.append(Knowledge(
            cwe=c.cwe, name=c.name, score=c.score,
            cause=fix.cause if fix else None, patch=fix.patch if fix else None,
            guideline=c.guidelines[0] if c.guidelines else None,
        ))
    return out


def gather(retriever: Retriever, probe: Probe, top_k: int = 3) -> list[Knowledge]:
    """Ask the retriever about the probe; keep the top_k CWEs."""
    return to_knowledge(retriever.retrieve(probe).candidates)[:top_k]

