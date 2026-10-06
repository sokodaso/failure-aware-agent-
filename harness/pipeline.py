from .analyze import analyze
from .draft import draft_code, extract_apis
from .knowledge import RetrieveFn, gather
from .llm import LLM
from .models import Analysis


def run(task: str, language: str, llm: LLM, retrieve: RetrieveFn, apis: list[str] | None = None,
        top_k: int = 3, files: dict[str, str] | None = None) -> Analysis:
    """v1: task -> retrieval -> FMEA -> FTA -> action insights."""
    knowledge = gather(task, language, retrieve, apis, top_k)
    return analyze(task, language, knowledge, llm, files)


def run_v2(task: str, language: str, llm: LLM, retrieve: RetrieveFn, top_k: int = 3,
           files: dict[str, str] | None = None) -> tuple[Analysis, str]:
    """v2: task -> draft -> retrieval (task only, as in v1) -> FMEA/FTA on the draft. Returns (analysis, draft).

    The draft's APIs are context for the analysis, not part of the retrieval query."""
    draft = draft_code(task, language, llm)
    apis = extract_apis(draft, language)
    knowledge = gather(task, language, retrieve, None, top_k)
    return analyze(task, language, knowledge, llm, files, draft, apis), draft

