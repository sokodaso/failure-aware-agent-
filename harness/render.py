"""Analysis -> the text handed to the coding agent."""

from .models import Analysis, FaultNode


def _tree(node: FaultNode, indent: int = 0) -> list[str]:
    tag = f"[{node.gate}] " if node.gate else ""
    kind = f" ({node.cause_type})" if node.cause_type != "n/a" else ""
    lines = [f"{'  ' * indent}- {tag}{node.event}{kind}"]
    for c in node.children:
        lines += _tree(c, indent + 1)
    return lines


def render_insights(a: Analysis) -> str:
    out = ["## Failure analysis (pre-implementation)",
           "Hypotheses to verify against the code, not established facts. Evidence level is shown per item.", ""]
    out.append("### Actions")
    for i, act in enumerate(a.actions, 1):
        where = f" in {', '.join(act.targets)}" if act.targets else ""
        out.append(f"{i}. {act.action}{where} (addresses {', '.join(act.failure_ids)})")
        if act.verification:
            out.append(f"   Verify: {act.verification}")
    out += ["", "### Failure modes (highest RPN first)"]
    for f in a.failure_modes:
        levels = "/".join(sorted({e.level for e in f.evidence})) or "inference"
        cwe = f" {f.cwe}" if f.cwe else ""
        out.append(f"- {f.id}{cwe} RPN {f.rpn} [{levels}] {f.component}: {f.failure_mode} -> {f.effect}")
        if f.control:
            out.append(f"  Control: {f.control}")
    for t in a.fault_trees:
        out += ["", f"### Fault tree {t.failure_mode_id}: {t.top_event}", *_tree(t.root)]
    return "\n".join(out)


def render_problem_statement(issue: str, a: Analysis) -> str:
    return f"{issue.strip()}\n\n{render_insights(a)}\n"
