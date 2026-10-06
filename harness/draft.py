"""v2 front end: the agent's own model drafts the code, and the APIs it calls give the analysis context."""

import ast
import re

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

