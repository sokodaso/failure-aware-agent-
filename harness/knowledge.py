"""Task -> retrieval -> the knowledge the generator is shown."""

from typing import Callable

from retrieval.models import CweCandidate, Hit

from .models import Knowledge

# (functionality query, language, expected apis) -> (hits, ranked CWE candidates)
RetrieveFn = Callable[[str, str, list[str]], tuple[list[Hit], list[CweCandidate]]]


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


def gather(task: str, language: str, retrieve: RetrieveFn, apis: list[str] | None = None,
           top_k: int = 3) -> list[Knowledge]:
    """Use the task text as the functionality query; keep the top_k CWEs."""
    _, candidates = retrieve(task, language, apis or [])
    return to_knowledge(candidates)[:top_k]
