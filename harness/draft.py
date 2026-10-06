"""v2 front end: the agent's own model drafts the code, and the APIs it calls become the retrieval key."""

import ast
import re
from dataclasses import dataclass, field

from .analyze import parse_json
from .llm import LLM

DRAFT_SYSTEM = "You are an expert programmer. Reply with one complete implementation in a single fenced code block."
C_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "else", "do", "catch", "defined"}
NOISE = {"print", "len", "range", "str", "int", "float", "list", "dict", "set", "tuple", "isinstance", "super"}


def draft_code(task: str, language: str, llm: LLM) -> str:
    reply = llm.chat(DRAFT_SYSTEM, f"Language: {language}\nTask:\n{task}")
    m = re.search(r"```[\w+-]*\n(.*?)```", reply, re.DOTALL)
    return (m.group(1) if m else reply).strip()


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def extract_apis(code: str, language: str) -> list[str]:
    """Call names in source order, de-duplicated. Python via ast; anything else via a call-site regex."""
    names: list[str] = []
    if language.lower() == "python":
        try:
            for node in ast.walk(ast.parse(code)):
                if isinstance(node, ast.Call) and (n := _dotted(node.func)) and n not in NOISE:
                    names.append(n)
            return list(dict.fromkeys(names))
        except SyntaxError:
            pass  # a draft that does not parse still has call sites
    for m in re.finditer(r"\b([A-Za-z_]\w*(?:(?:->|\.|::)\w+)*)\s*\(", code):
        if m.group(1) not in C_KEYWORDS | NOISE:
            names.append(m.group(1))
    return list(dict.fromkeys(names))


@dataclass
class Component:
    description: str  # one functionality sentence, the style the graph is indexed by
    apis: list[str] = field(default_factory=list)


MAX_COMPONENTS = 4
SPLIT_SYSTEM = "You decompose code into components. Reply with a single JSON object and nothing else."
SPLIT_PROMPT = """Task:
{task}

Implementation ({language}):
```
{code}
```

Break the implementation into at most {n} components, one per place where it depends on or acts on something
outside plain computation: the filesystem, processes, the network, a database, parsing an external format,
memory, or cryptography. For each component give "description": one sentence saying what it does, written like a
function summary (e.g. "Reads a file and returns its lines"), and "apis": the calls it makes, spelled as in the code.
Return: {{"components": [{{"description": "...", "apis": ["..."]}}]}}"""


def split_components(draft: str, task: str, language: str, llm: LLM, apis: list[str]) -> list[Component]:
    """Failure-boundary components of the draft. Falls back to one task-level component."""
    fallback = [Component(task, apis)]
    try:
        raw = parse_json(llm.chat(SPLIT_SYSTEM, SPLIT_PROMPT.format(task=task, language=language, code=draft,
                                                                    n=MAX_COMPONENTS)))
        comps = [Component(str(c["description"]), [str(a) for a in c.get("apis") or []])
                 for c in raw.get("components") or [] if c.get("description")]
    except (ValueError, KeyError, TypeError, AttributeError):
        return fallback
    return comps[:MAX_COMPONENTS] or fallback
