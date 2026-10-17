from dataclasses import dataclass, field


@dataclass
class FixInfo:
    """What the FIXES edge records about the vulnerable/fixed pair this version belongs to."""
    partner_id: str
    patch: str | None
    cause: str | None


@dataclass
class Version:
    id: str
    language: str | None
    role: str  # "vulnerable" | "reported_fixed"
    pair_available: bool
    cwes: list[str]
    code: str | None
    apis: list[str]  # raw API.text spellings this function calls
    fix: FixInfo | None = None
    # filled in by compare.annotate_api_overlap
    api_overlap: float = 0.0
    matched_apis: list[str] = field(default_factory=list)


@dataclass
class Hit:
    functionality_id: str
    text: str
    similarity: float
    versions: list[Version]


@dataclass
class Evidence:
    version_id: str
    score: float
    similarity: float
    api_overlap: float
    fix: FixInfo | None


@dataclass
class CweCandidate:
    cwe: str
    score: float
    evidence: list[Evidence]  # weakness-exhibiting versions backing this CWE, best first
    name: str = ""
    summary: str = ""
    guidelines: list[str] = field(default_factory=list)
    attack_patterns: list[str] = field(default_factory=list)
