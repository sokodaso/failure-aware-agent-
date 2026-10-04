"""Failure analysis: retrieved knowledge + the failure-analysis skill -> FMEA, FTA, actions.

The model proposes; this module validates. RPN is computed here, never trusted from the model,
FTA runs only on the top failure modes and within the skill's size limits, and a claim of
"history" evidence is downgraded to "inference" unless it names a CWE that was actually retrieved.
"""

import json
import re
from pathlib import Path

from .llm import LLM
from .models import Action, Analysis, Evidence, FailureMode, FaultNode, FaultTree, Knowledge

SKILL_DIR = Path(__file__).resolve().parent.parent / "skills" / "failure-analysis"
LEVELS = ("repository", "task", "history", "inference")
VIEWPOINTS = ("functional", "data", "control_flow", "interface", "dependency", "security")
FTA_TOP_N, MAX_DEPTH, MAX_CHILDREN, MAX_NODES = 5, 3, 4, 15
MAX_CAUSE, MAX_PATCH, MAX_GUIDELINE, MAX_FILE = 600, 1500, 500, 6000

SYSTEM = """You perform pre-implementation failure analysis for a coding agent that has NOT yet
written any code. Follow the skill below. Reply with a single JSON object and nothing else."""

SCALES = """Severity: 1 cosmetic, 2 degraded but recoverable, 3 wrong result for some inputs,
4 data loss / corruption / security-relevant, 5 catastrophic or propagates to other subsystems.
Likelihood: 1 remote, 2 unlikely, 3 possible, 4 reasonably probable, 5 frequent (seen in the
analysis AND in retrieved history). Evidence levels, strongest first: repository, task, history,
inference. Use "history" only for failures backed by a retrieved weakness and cite its CWE id in
"ref"; anything you reasoned out yourself is "inference"."""

FMEA_CONTRACT = f"""{SCALES}
Return: {{"failure_modes": [{{"id": "FM1", "component": "...", "failure_mode": "Under condition X,
Y fails to Z by D", "viewpoint": "{'|'.join(VIEWPOINTS)}", "effect": "...", "severity": 1-5,
"likelihood": 1-5, "evidence": [{{"level": "...", "ref": "..."}}], "cwe": "CWE-n or null",
"control": "preventive constraint"}}]}}"""

FTA_CONTRACT = f"""You are given the highest-RPN failure modes. For each, build a fault tree: the
failure's effect is the top event; each node has 2-{MAX_CHILDREN} children, a gate (AND|OR),
a cause_type (timing|value|omission|n/a); basic events have no children and no gate. Max depth
{MAX_DEPTH}, max {MAX_NODES} nodes per tree. Then give the actions a coding agent should take
BEFORE and WHILE implementing, each tied to failure ids and tied to a check that would show it works.
Return: {{"fault_trees": [{{"failure_mode_id": "FM1", "top_event": "...", "root": {{"event": "...",
"gate": "OR", "cause_type": "value", "children": [...]}}}}], "actions": [{{"action": "...",
"targets": ["file or function"], "failure_ids": ["FM1"], "verification": "..."}}]}}"""


def load_skill() -> str:
    parts = [(SKILL_DIR / "SKILL.md").read_text()]
    for name in ("fmea.txt", "fta.txt"):
        parts.append(f"--- {name} ---\n" + (SKILL_DIR / "schemas" / name).read_text())
    return "\n\n".join(parts)


def _clip(text: str | None, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + " ...[truncated]"


def render_knowledge(knowledge: list[Knowledge]) -> str:
    if not knowledge:
        return "(no relevant historical failures were retrieved)"
    blocks = []
    for k in knowledge:
        lines = [f"### {k.cwe}: {k.name}"]
        if k.cause:
            lines.append("Cause seen in similar real code: " + _clip(k.cause, MAX_CAUSE))
        if k.patch:
            lines.append("Fix that was applied (diff excerpt):\n" + _clip(k.patch, MAX_PATCH))
        if k.guideline:
            lines.append("Guideline: " + _clip(k.guideline, MAX_GUIDELINE))
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def build_context(task: str, language: str, knowledge: list[Knowledge], files: dict[str, str] | None = None) -> str:
    out = [f"Language: {language}", f"Task:\n{task}"]
    for path, text in (files or {}).items():
        out.append(f"Repository file {path}:\n{_clip(text, MAX_FILE)}")
    out.append("Retrieved historical failures:\n\n" + render_knowledge(knowledge))
    return "\n\n".join(out)


def fmea_prompt(context: str) -> str:
    return f"{context}\n\nPerform the FMEA now.\n{FMEA_CONTRACT}"


def fta_prompt(context: str, top: list[FailureMode]) -> str:
    rows = json.dumps([{"id": f.id, "component": f.component, "failure_mode": f.failure_mode,
                        "effect": f.effect, "rpn": f.rpn} for f in top], indent=1)
    return f"{context}\n\nHighest-RPN failure modes:\n{rows}\n\n{FTA_CONTRACT}"


def parse_json(response: str) -> dict:
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", response, re.DOTALL)
    text = m.group(1) if m else response[response.find("{"): response.rfind("}") + 1]
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def _ask(llm: LLM, system: str, user: str) -> dict:
    """One retry that shows the model its own parse error."""
    response = llm.chat(system, user)
    try:
        return parse_json(response)
    except ValueError as e:  # JSONDecodeError subclasses ValueError
        retry = f"{user}\n\nYour previous reply was not valid JSON ({e}). Reply with only the JSON object."
        return parse_json(llm.chat(system, retry))


def _clamp(value, default: int) -> int:
    try:
        return min(5, max(1, int(value)))
    except (TypeError, ValueError):
        return default


def validate_failure_modes(raw: list[dict], retrieved: set[str], notes: list[str]) -> list[FailureMode]:
    modes, seen = [], set()
    for i, r in enumerate(raw, 1):
        fid = str(r.get("id") or f"FM{i}")
        if fid in seen or not r.get("failure_mode"):
            notes.append(f"dropped failure mode {fid}: duplicate id or empty")
            continue
        seen.add(fid)
        cwe = r.get("cwe") or None
        evidence = []
        for e in r.get("evidence") or []:
            level, ref = e.get("level"), str(e.get("ref", ""))
            if level not in LEVELS:
                level = "inference"
            if level == "history" and not (retrieved & set(re.findall(r"CWE-\d+", ref + " " + (cwe or "")))):
                notes.append(f"{fid}: 'history' evidence cites no retrieved CWE; downgraded to inference")
                level = "inference"
            evidence.append(Evidence(level, ref))
        viewpoint = r.get("viewpoint") if r.get("viewpoint") in VIEWPOINTS else "functional"
        modes.append(FailureMode(
            fid, str(r.get("component", "")), r["failure_mode"], viewpoint, str(r.get("effect", "")),
            _clamp(r.get("severity"), 3), _clamp(r.get("likelihood"), 3), evidence, cwe, str(r.get("control", "")),
        ))
    return sorted(modes, key=lambda f: -f.rpn)


def prune_tree(raw: dict) -> FaultNode:
    """Breadth-first copy honouring MAX_DEPTH, MAX_CHILDREN and MAX_NODES."""
    def node(d: dict) -> FaultNode:
        gate = d.get("gate") if d.get("gate") in ("AND", "OR") else None
        cause = d.get("cause_type") if d.get("cause_type") in ("timing", "value", "omission") else "n/a"
        return FaultNode(str(d.get("event", "")), gate, cause)

    root = node(raw)
    queue, count = [(root, raw, 1)], 1
    while queue:
        parent, src, depth = queue.pop(0)
        if depth > MAX_DEPTH:
            continue
        for child in (src.get("children") or [])[:MAX_CHILDREN]:
            if count >= MAX_NODES:
                break
            c = node(child)
            parent.children.append(c)
            count += 1
            queue.append((c, child, depth + 1))
        if not parent.children:
            parent.gate = None
    return root


def validate_fta(raw: dict, modes: list[FailureMode], notes: list[str]) -> tuple[list[FaultTree], list[Action]]:
    allowed = {f.id for f in modes[:FTA_TOP_N]}
    known = {f.id for f in modes}
    trees = []
    for t in raw.get("fault_trees") or []:
        if t.get("failure_mode_id") not in allowed or not t.get("root"):
            notes.append(f"dropped fault tree for {t.get('failure_mode_id')}: not a top-{FTA_TOP_N} failure mode")
            continue
        trees.append(FaultTree(t["failure_mode_id"], str(t.get("top_event", "")), prune_tree(t["root"])))
    actions = []
    for a in raw.get("actions") or []:
        ids = [i for i in a.get("failure_ids") or [] if i in known]
        if not a.get("action") or not ids:
            notes.append(f"dropped action {str(a.get('action'))[:40]!r}: no valid failure id")
            continue
        actions.append(Action(a["action"], list(a.get("targets") or []), ids, str(a.get("verification", ""))))
    return trees, actions


def analyze(task: str, language: str, knowledge: list[Knowledge], llm: LLM,
            files: dict[str, str] | None = None) -> Analysis:
    system = f"{SYSTEM}\n\n{load_skill()}"
    context = build_context(task, language, knowledge, files)
    notes: list[str] = []
    retrieved = {k.cwe for k in knowledge}

    modes = validate_failure_modes(_ask(llm, system, fmea_prompt(context)).get("failure_modes") or [], retrieved, notes)
    trees, actions = [], []
    if modes:
        raw = _ask(llm, system, fta_prompt(context, modes[:FTA_TOP_N]))
        trees, actions = validate_fta(raw, modes, notes)
    return Analysis(task, language, knowledge, modes, trees, actions, notes)
