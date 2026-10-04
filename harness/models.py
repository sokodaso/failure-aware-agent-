from dataclasses import dataclass, field


@dataclass
class Knowledge:
    """What the graph knows about one CWE, taken from the retrieved similar functions."""
    cwe: str
    name: str
    score: float
    cause: str | None = None  # vulnerability_cause from a real fix pair
    patch: str | None = None  # the fix diff
    guideline: str | None = None


@dataclass
class Evidence:
    level: str  # repository | task | history | inference  (the skill's evidence hierarchy)
    ref: str = ""


@dataclass
class FailureMode:
    id: str
    component: str
    failure_mode: str
    viewpoint: str  # functional | data | control_flow | interface | dependency | security
    effect: str
    severity: int  # 1-5
    likelihood: int  # 1-5
    evidence: list[Evidence] = field(default_factory=list)
    cwe: str | None = None
    control: str = ""  # preventive constraint

    @property
    def rpn(self) -> int:
        return self.severity * self.likelihood


@dataclass
class FaultNode:
    event: str
    gate: str | None = None  # AND | OR, None on a basic event
    cause_type: str = "n/a"  # timing | value | omission | n/a
    children: list["FaultNode"] = field(default_factory=list)


@dataclass
class FaultTree:
    failure_mode_id: str
    top_event: str
    root: FaultNode


@dataclass
class Action:
    action: str
    targets: list[str] = field(default_factory=list)  # files / functions the agent should touch
    failure_ids: list[str] = field(default_factory=list)
    verification: str = ""  # a test or check that would show the failure is handled


@dataclass
class Analysis:
    task: str
    language: str
    knowledge: list[Knowledge]
    failure_modes: list[FailureMode]  # sorted by rpn, highest first
    fault_trees: list[FaultTree]
    actions: list[Action]
    notes: list[str] = field(default_factory=list)  # what validation corrected or dropped
