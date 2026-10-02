"""
Second build increment: takes the 16 filtered per-CWE graphs (data/filtered_kg,
produced by filter_kg.py) and turns them into one merged, Neo4j-ready graph
that matches the Fig. 2 data model from "Fagent structure.pdf":

  Fixed function version --FIXES--> Function version --IMPLEMENTS--> Functionality
                                          |--CALLS--> API
                                          |--EXHIBITS_WEAKNESS--> CWE
  CVE --CLASSIFIED_AS--> CWE
  AttackPattern (CAPEC) --EXPLOITS_WEAKNESS--> CWE
  SecurityGuideline --MITIGATES--> CWE

Design decisions made in conversation (2026-09-28):
- KnowledgeExample nodes are folded away: their patch diff and
  vulnerability_cause narrative become properties on the FIXES relationship
  between the fixed and vulnerable FunctionVersion; their DESCRIBES_WEAKNESS
  edge becomes an EXHIBITS_WEAKNESS edge from each of the two FunctionVersions.
- Functionality is promoted from a FunctionVersion.functionality string
  property to its own node (deduplicated by exact text, id = sha256 of the
  text), carrying a local sentence-transformers embedding for similarity
  search.
- Labels/relationship types renamed to match the paper's vocabulary:
  Weakness->CWE, APICallToken->API, Vulnerability->CVE,
  HAS_REPORTED_WEAKNESS/HAS_DATASET_CWE_CONTEXT->EXHIBITS_WEAKNESS,
  RELATED_WEAKNESS->EXPLOITS_WEAKNESS, REPORTED_FIX_OF->FIXES. Everything else
  (CALLS, HAS_CODE, HAS_CODE_SLICE, ASSOCIATED_WITH_COMMIT, IN_PROJECT,
  HAS_API_TOKEN, HAS_GUIDELINE, MITIGATES, CLASSIFIED_AS, OBSERVED_EXAMPLE_OF,
  DESCRIBES_WEAKNESS from LanguageSpecificKnowledge) keeps its original name.

Normalisation decisions (2026-10-02):
- Language labels are canonicalised once, here, for every node and relationship `language`
  property: the rescue dataset's "py" becomes "python". "c" and "cpp" stay distinct labels.
- Every FunctionVersion gets an explicit `role`. The DiverseVul functions were kept
  vulnerable-only by design, so they carry no role in the source; they are assigned
  role="vulnerable" (role_status records that it was assigned, not read from the source)
  and pair_available=False. FunctionVersions on a FIXES edge get pair_available=True.
"""

import hashlib
import json
from pathlib import Path

FILTERED_DIR = Path(__file__).parent.parent / "data" / "filtered_kg"
OUT_DIR = Path(__file__).parent.parent / "data" / "final_kg"
OUT_PATH = OUT_DIR / "graph.json"

TARGET_CWES = [22, 78, 79, 89, 119, 125, 190, 295, 326, 327, 416, 476, 502, 611, 732, 787]

LABEL_RENAME = {
    "Weakness": "CWE",
    "APICallToken": "API",
    "Vulnerability": "CVE",
}

REL_RENAME = {
    "HAS_REPORTED_WEAKNESS": "EXHIBITS_WEAKNESS",
    "HAS_DATASET_CWE_CONTEXT": "EXHIBITS_WEAKNESS",
    "RELATED_WEAKNESS": "EXPLOITS_WEAKNESS",
}

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# Spelling variants of the same language. c/cpp are deliberately not merged.
LANGUAGE_ALIASES = {"py": "python"}


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def flatten_value(value):
    """Neo4j properties must be primitives or arrays of primitives."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value):
        return value
    return json.dumps(value)


def flatten_props(entity_or_rel: dict, skip: set) -> dict:
    props = {}
    for k, v in entity_or_rel.items():
        if k in skip:
            continue
        fv = flatten_value(v)
        if k == "language" and isinstance(fv, str):
            fv = LANGUAGE_ALIASES.get(fv.lower(), fv.lower())
        if fv is not None:
            props[k] = fv
    return props


def load_merged():
    """Merge the 16 filtered files into one global entity map + relationship list."""
    entities = {}
    relationships = []
    seen_rel_keys = set()
    for cwe_num in TARGET_CWES:
        data = json.loads((FILTERED_DIR / f"cwe{cwe_num}_kg.filtered.json").read_text())
        for e in data["entities"]:
            entities.setdefault(e["id"], e)
        for r in data["relationships"]:
            key = (r["source"], r["type"], r["target"])
            if key in seen_rel_keys:
                continue
            seen_rel_keys.add(key)
            relationships.append(r)
    return entities, relationships


def build():
    entities, relationships = load_merged()
    type_of = {eid: e["type"] for eid, e in entities.items()}

    ke_vuln, ke_fixed, ke_cwe = {}, {}, {}
    reported_fix_of = []  # (fixed_id, vulnerable_id, rel_dict)
    other_rels = []  # rels to pass through mostly as-is

    for r in relationships:
        t = r["type"]
        if t == "HAS_VULNERABLE_VERSION":
            ke_vuln[r["source"]] = r["target"]
        elif t == "HAS_REPORTED_FIXED_VERSION":
            ke_fixed[r["source"]] = r["target"]
        elif t == "DESCRIBES_WEAKNESS" and type_of.get(r["source"]) == "KnowledgeExample":
            ke_cwe[r["source"]] = r["target"]
        elif t == "REPORTED_FIX_OF":
            reported_fix_of.append((r["source"], r["target"], r))
        else:
            other_rels.append(r)

    # EXHIBITS_WEAKNESS pairs, deduplicated.
    exhibits_pairs = set()
    for r in other_rels:
        if r["type"] in ("HAS_REPORTED_WEAKNESS", "HAS_DATASET_CWE_CONTEXT"):
            exhibits_pairs.add((r["source"], r["target"]))
    for ke_id, cwe_id in ke_cwe.items():
        v, f = ke_vuln.get(ke_id), ke_fixed.get(ke_id)
        if v:
            exhibits_pairs.add((v, cwe_id))
        if f:
            exhibits_pairs.add((f, cwe_id))

    # FIXES: enrich REPORTED_FIX_OF with the folded KnowledgeExample's patch/cause.
    fixes_extra = {}
    for ke_id, v in ke_vuln.items():
        f = ke_fixed.get(ke_id)
        if not f:
            continue
        ke = entities[ke_id]
        extra = flatten_props(ke, skip={"id", "type"})
        extra["knowledge_example_id"] = ke_id
        fixes_extra[(f, v)] = extra

    final_relationships = []

    for fixed_id, vuln_id, r in reported_fix_of:
        props = flatten_props(r, skip={"id", "type", "source", "target"})
        props.update(fixes_extra.get((fixed_id, vuln_id), {}))
        final_relationships.append({
            "type": "FIXES",
            "source": fixed_id,
            "target": vuln_id,
            "source_label": "FunctionVersion",
            "target_label": "FunctionVersion",
            "props": props,
        })

    for source, target in exhibits_pairs:
        final_relationships.append({
            "type": "EXHIBITS_WEAKNESS",
            "source": source,
            "target": target,
            "source_label": "FunctionVersion",
            "target_label": "CWE",
            "props": {},
        })

    label_of_final = {}

    def resolve_label(entity_type: str) -> str:
        return LABEL_RENAME.get(entity_type, entity_type)

    for r in other_rels:
        t = r["type"]
        if t in ("HAS_REPORTED_WEAKNESS", "HAS_DATASET_CWE_CONTEXT"):
            continue  # already folded into EXHIBITS_WEAKNESS
        new_type = REL_RENAME.get(t, t)
        props = flatten_props(r, skip={"id", "type", "source", "target"})
        final_relationships.append({
            "type": new_type,
            "source": r["source"],
            "target": r["target"],
            "source_label": resolve_label(type_of.get(r["source"], "?")),
            "target_label": resolve_label(type_of.get(r["target"], "?")),
            "props": props,
        })

    paired_ids = {r["source"] for r in final_relationships if r["type"] == "FIXES"} | {
        r["target"] for r in final_relationships if r["type"] == "FIXES"}

    # Nodes: every entity except KnowledgeExample (folded away).
    nodes = []
    functionality_nodes = {}  # func_id -> {"id": ..., "text": ...}

    for eid, e in entities.items():
        etype = e["type"]
        if etype == "KnowledgeExample":
            continue
        label = resolve_label(etype)
        skip = {"id", "type"}
        if etype == "FunctionVersion":
            skip = skip | {"functionality", "functionality_source"}
        props = flatten_props(e, skip=skip)
        if etype == "FunctionVersion":
            props["pair_available"] = eid in paired_ids
            if not props.get("role"):
                props["role"] = "vulnerable"
                props["role_status"] = "assigned_vulnerable_only_dataset"
        nodes.append({"label": label, "id": eid, "props": props})

        if etype == "FunctionVersion" and e.get("functionality"):
            text = e["functionality"]
            func_id = f"functionality:{sha256(text)}"
            functionality_nodes.setdefault(func_id, {"id": func_id, "text": text})
            implements_props = {}
            if e.get("functionality_source"):
                implements_props["functionality_source"] = e["functionality_source"]
            final_relationships.append({
                "type": "IMPLEMENTS",
                "source": eid,
                "target": func_id,
                "source_label": "FunctionVersion",
                "target_label": "Functionality",
                "props": implements_props,
            })

    print(f"Embedding {len(functionality_nodes)} unique functionality descriptions "
          f"with {EMBEDDING_MODEL_NAME} ...")
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    func_items = list(functionality_nodes.values())
    texts = [f["text"] for f in func_items]
    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)

    for f, emb in zip(func_items, embeddings):
        nodes.append({
            "label": "Functionality",
            "id": f["id"],
            "props": {"text": f["text"], "embedding": [float(x) for x in emb]},
        })

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    graph = {
        "embedding_model": EMBEDDING_MODEL_NAME,
        "embedding_dimensions": len(embeddings[0]) if len(embeddings) else 0,
        "nodes": nodes,
        "relationships": final_relationships,
    }
    OUT_PATH.write_text(json.dumps(graph))

    from collections import Counter
    node_counts = Counter(n["label"] for n in nodes)
    rel_counts = Counter(r["type"] for r in final_relationships)
    print("\nNode counts:")
    for label, c in node_counts.most_common():
        print(f"  {label:<25} {c}")
    print("\nRelationship counts:")
    for rtype, c in rel_counts.most_common():
        print(f"  {rtype:<25} {c}")
    print(f"\nWrote {OUT_PATH}")


if __name__ == "__main__":
    build()
