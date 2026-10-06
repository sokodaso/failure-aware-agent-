from .analyze import analyze
from .draft import draft_code, extract_apis, split_components
from .knowledge import RetrieveFn, gather, gather_components
from .llm import LLM
from .models import Analysis


def run(task: str, language: str, llm: LLM, retrieve: RetrieveFn, apis: list[str] | None = None,
        top_k: int = 3, files: dict[str, str] | None = None) -> Analysis:
    """v1: task -> retrieval -> FMEA -> FTA -> action insights."""
    knowledge = gather(task, language, retrieve, apis, top_k)
    return analyze(task, language, knowledge, llm, files)


def run_v2(task: str, language: str, llm: LLM, retrieve: RetrieveFn, top_k: int = 3,
           files: dict[str, str] | None = None) -> tuple[Analysis, str]:
    """v2: task -> draft -> APIs -> retrieval (task + APIs) -> FMEA/FTA on the draft. Returns (analysis, draft)."""
    draft = draft_code(task, language, llm)
    apis = extract_apis(draft, language)
    knowledge = gather(task, language, retrieve, apis, top_k)
    return analyze(task, language, knowledge, llm, files, draft, apis), draft


def run_v3(task: str, language: str, llm: LLM, retrieve: RetrieveFn, top_k: int = 3,
           files: dict[str, str] | None = None) -> tuple[Analysis, str]:
    """v3 = v2 with one retrieval per failure-boundary component of the draft instead of one per task."""
    draft = draft_code(task, language, llm)
    apis = extract_apis(draft, language)
    components = split_components(draft, task, language, llm, apis)
    knowledge = gather_components(components, language, retrieve, top_k)
    return analyze(task, language, knowledge, llm, files, draft, apis), draft
