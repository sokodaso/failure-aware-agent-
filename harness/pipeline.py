from .analyze import analyze
from .draft import draft_code, extract_apis
from retrieval.common.base import Probe, Retriever

from .knowledge import gather
from .llm import LLM
from .models import Analysis


def run(task: str, language: str, llm: LLM, retriever: Retriever, apis: list[str] | None = None,
        top_k: int = 3, files: dict[str, str] | None = None) -> Analysis:
    """v1: task -> retrieval -> FMEA -> FTA -> action insights."""
    knowledge = gather(retriever, Probe(task, language, apis=apis or []), top_k)
    return analyze(task, language, knowledge, llm, files)


def run_v2(task: str, language: str, llm: LLM, retriever: Retriever, top_k: int = 3,
           files: dict[str, str] | None = None) -> tuple[Analysis, str]:
    """v2: task -> draft -> retrieval (task only, as in v1) -> FMEA/FTA on the draft. Returns (analysis, draft).

    The draft and its APIs go to the retriever in the probe; fagent retrieval ignores them unless told to use APIs."""
    draft = draft_code(task, language, llm)
    apis = extract_apis(draft, language)
    knowledge = gather(retriever, Probe(task, language, draft=draft, apis=apis), top_k)
    return analyze(task, language, knowledge, llm, files, draft, apis), draft

