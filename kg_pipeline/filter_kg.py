"""
Filters the raw per-CWE knowledge graphs produced by cwe89_kg_pipeline down to
the 16-CWE subset this project uses, keeping only entities that are useful as
retrieval examples.

Scope decisions (see conversation, 2026-09-28):
- CWEs: 22, 78, 79, 89, 119, 125, 190, 295, 326, 327, 416, 476, 502, 611, 732,
  787. CWE-377 and CWE-676 are excluded entirely.
- A FunctionVersion counts as a usable example if its `functionality` field is
  not null, whether it came from a RESCUE KnowledgeExample pair or a
  standalone DiverseVul HAS_REPORTED_WEAKNESS record. A KnowledgeExample pair
  is kept if either its vulnerable or fixed FunctionVersion survives (in the
  source data these two are always both-null or both-set together, but this
  is defensive).
- Entities attached directly to the CWE node -- SecurityGuideline,
  AttackPattern, Vulnerability (CVE), LanguageSpecificKnowledge -- are always
  kept regardless of example survival, since they aren't tied to a specific
  code example.
- Everything else (CodeArtifact, Commit, Project, APICallToken reached only
  through a dropped FunctionVersion) is pruned as an orphan.
"""

import json
from pathlib import Path

SOURCE_DIR = Path("/Users/sammieokodaso/Downloads/cwe89_kg_pipeline/output")
OUT_DIR = Path(__file__).parent.parent / "data" / "filtered_kg"

TARGET_CWES = [22, 78, 79, 89, 119, 125, 190, 295, 326, 327, 416, 476, 502, 611, 732, 787]

ALWAYS_KEEP_TYPES = {
    "Weakness",
    "SecurityGuideline",
    "AttackPattern",
    "Vulnerability",
    "LanguageSpecificKnowledge",
}


def source_path(cwe_num: int) -> Path:
    if cwe_num == 89:
        return SOURCE_DIR / "cwe89_kg_v2.json"
    return SOURCE_DIR / f"cwe{cwe_num}_kg.json"


def filter_cwe(cwe_num: int) -> dict:
    data = json.loads(source_path(cwe_num).read_text())
    entities = data["entities"]
    relationships = data["relationships"]
    ent_by_id = {e["id"]: e for e in entities}

    rels_by_type: dict[str, list[dict]] = {}
    for r in relationships:
        rels_by_type.setdefault(r["type"], []).append(r)

    fv_ids = {e["id"] for e in entities if e["type"] == "FunctionVersion"}
    non_null_fv = {
        e["id"] for e in entities
        if e["type"] == "FunctionVersion" and e.get("functionality") is not None
    }

    # KnowledgeExample pairs: keep both sides if either side is non-null.
    ke_vuln = {r["source"]: r["target"] for r in rels_by_type.get("HAS_VULNERABLE_VERSION", [])}
    ke_fixed = {r["source"]: r["target"] for r in rels_by_type.get("HAS_REPORTED_FIXED_VERSION", [])}
    ke_ids = {e["id"] for e in entities if e["type"] == "KnowledgeExample"}

    keep_fv: set[str] = set(non_null_fv)
    keep_ke: set[str] = set()
    for ke_id in ke_ids:
        v = ke_vuln.get(ke_id)
        f = ke_fixed.get(ke_id)
        survives = (v in non_null_fv) or (f in non_null_fv)
        if survives:
            keep_ke.add(ke_id)
            if v:
                keep_fv.add(v)
            if f:
                keep_fv.add(f)

    keep_always = {e["id"] for e in entities if e["type"] in ALWAYS_KEEP_TYPES}

    # Reachable via a surviving FunctionVersion.
    code_artifacts = {
        r["target"] for r in rels_by_type.get("HAS_CODE", []) + rels_by_type.get("HAS_CODE_SLICE", [])
        if r["source"] in keep_fv
    }
    commits = {
        r["target"] for r in rels_by_type.get("ASSOCIATED_WITH_COMMIT", [])
        if r["source"] in keep_fv
    }
    projects = {
        r["target"] for r in rels_by_type.get("IN_PROJECT", [])
        if r["source"] in commits
    }
    api_tokens_via_fv = {
        r["target"] for r in rels_by_type.get("CALLS", [])
        if r["source"] in keep_fv
    }
    # Tokens reachable from the always-kept LanguageSpecificKnowledge side.
    api_tokens_via_lsk = {
        r["target"] for r in rels_by_type.get("HAS_API_TOKEN", [])
        if r["source"] in keep_always
    }

    final_ids = (
        keep_fv | keep_ke | keep_always | code_artifacts | commits | projects
        | api_tokens_via_fv | api_tokens_via_lsk
    )

    final_entities = [e for e in entities if e["id"] in final_ids]
    final_relationships = [
        r for r in relationships if r["source"] in final_ids and r["target"] in final_ids
    ]

    filtered = dict(data)
    filtered["entities"] = final_entities
    filtered["relationships"] = final_relationships
    filtered["filter_stats"] = {
        "source_entities": len(entities),
        "kept_entities": len(final_entities),
        "source_relationships": len(relationships),
        "kept_relationships": len(final_relationships),
        "function_versions_total": len(fv_ids),
        "function_versions_kept": len(keep_fv),
        "knowledge_examples_total": len(ke_ids),
        "knowledge_examples_kept": len(keep_ke),
    }
    return filtered


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    summary = []
    for cwe_num in TARGET_CWES:
        filtered = filter_cwe(cwe_num)
        out_path = OUT_DIR / f"cwe{cwe_num}_kg.filtered.json"
        out_path.write_text(json.dumps(filtered, indent=2))
        stats = filtered["filter_stats"]
        summary.append((cwe_num, stats))
        print(
            f"CWE-{cwe_num}: entities {stats['source_entities']:>5} -> {stats['kept_entities']:>5}  "
            f"| FunctionVersion {stats['function_versions_total']:>5} -> {stats['function_versions_kept']:>4}  "
            f"| KnowledgeExample {stats['knowledge_examples_total']:>4} -> {stats['knowledge_examples_kept']:>4}"
        )

    total_before = sum(s["source_entities"] for _, s in summary)
    total_after = sum(s["kept_entities"] for _, s in summary)
    print(f"\nTotal entities across 16 CWEs: {total_before} -> {total_after}")


if __name__ == "__main__":
    main()
