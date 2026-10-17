"""What every retrieval design shares: the input it is given and the shape of what it returns."""

from dataclasses import dataclass, field
from typing import Protocol

from .models import CweCandidate


@dataclass
class Probe:
    """Everything known about the task when retrieval runs. A design uses the fields it needs."""
    task: str
    language: str
    summary: str = ""  # one sentence on what the code must do
    draft: str = ""  # the agent model's first implementation (draft-first runs only)
    apis: list[str] = field(default_factory=list)  # calls the draft makes, or APIs the caller expects


@dataclass
class Retrieval:
    candidates: list[CweCandidate]  # ranked CWEs with their context, best first
    trace: dict = field(default_factory=dict)  # design-specific detail for logging


class Retriever(Protocol):
    def retrieve(self, probe: Probe) -> Retrieval: ...
