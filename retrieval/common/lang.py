"""Which stored language labels count as a match for a requested language.

Labels in the graph are canonical (py was folded into python at build time). The one policy
choice left is that C and C++ are treated as compatible: C++ code calls the C library, and
DiverseVul's c/cpp label comes from a project-to-language mapping, so it is not a hard boundary.
"""

_COMPATIBLE = {"c": ["c", "cpp"], "cpp": ["c", "cpp"]}


def compatible_languages(language: str | None) -> list[str]:
    """Stored labels to accept for `language`. Empty list means no language filter."""
    if not language:
        return []
    lang = language.lower()
    return _COMPATIBLE.get(lang, [lang])
