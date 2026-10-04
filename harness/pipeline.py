from .analyze import analyze
from .knowledge import RetrieveFn, gather
from .llm import LLM
from .models import Analysis


def run(task: str, language: str, llm: LLM, retrieve: RetrieveFn, apis: list[str] | None = None,
        top_k: int = 3, files: dict[str, str] | None = None) -> Analysis:
    """task -> retrieval -> FMEA -> FTA -> action insights."""
    knowledge = gather(task, language, retrieve, apis, top_k)
    return analyze(task, language, knowledge, llm, files)
