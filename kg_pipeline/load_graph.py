"""
Loads data/final_kg/graph.json (produced by build_final_graph.py) into Neo4j.

Idempotent: every node is MERGEd on (label, id), every relationship is
MERGEd on (source, type, target), so re-running this after a rebuild just
updates properties rather than duplicating anything. Uniqueness constraints
are created first so the MERGEs are backed by an index.
"""

import json
import os
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

GRAPH_PATH = Path(__file__).parent.parent / "data" / "final_kg" / "graph.json"
BATCH_SIZE = 2000

ALL_LABELS = [
    "CWE", "FunctionVersion", "Functionality", "API", "CodeArtifact",
    "Commit", "Project", "LanguageSpecificKnowledge", "SecurityGuideline",
    "AttackPattern", "CVE",
]


def chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def create_constraints(session):
    for label in ALL_LABELS:
        session.run(
            f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:`{label}`) REQUIRE n.id IS UNIQUE"
        )


def load_nodes(session, nodes):
    by_label = defaultdict(list)
    for n in nodes:
        by_label[n["label"]].append({"id": n["id"], "props": n["props"]})

    for label, rows in by_label.items():
        for batch in chunks(rows, BATCH_SIZE):
            session.run(
                f"""
                UNWIND $rows AS row
                MERGE (n:`{label}` {{id: row.id}})
                SET n += row.props
                """,
                rows=batch,
            )
        print(f"  loaded {len(rows):>6} :{label}")


def load_relationships(session, relationships):
    by_group = defaultdict(list)
    for r in relationships:
        key = (r["type"], r["source_label"], r["target_label"])
        by_group[key].append({"source": r["source"], "target": r["target"], "props": r["props"]})

    for (rtype, source_label, target_label), rows in by_group.items():
        for batch in chunks(rows, BATCH_SIZE):
            session.run(
                f"""
                UNWIND $rows AS row
                MATCH (a:`{source_label}` {{id: row.source}})
                MATCH (b:`{target_label}` {{id: row.target}})
                MERGE (a)-[r:`{rtype}`]->(b)
                SET r += row.props
                """,
                rows=batch,
            )
        print(f"  loaded {len(rows):>6} :{source_label}-[{rtype}]->:{target_label}")


def create_vector_index(session, dimensions: int):
    session.run(
        """
        CREATE VECTOR INDEX functionality_embedding IF NOT EXISTS
        FOR (n:Functionality) ON (n.embedding)
        OPTIONS {indexConfig: {
          `vector.dimensions`: $dims,
          `vector.similarity_function`: 'cosine'
        }}
        """,
        dims=dimensions,
    )


def verify(session):
    result = session.run(
        "MATCH (n) RETURN labels(n)[0] AS label, count(*) AS c ORDER BY c DESC"
    ).data()
    print("\nNode counts in Neo4j:")
    for row in result:
        print(f"  {row['label']:<25} {row['c']}")

    result = session.run(
        "MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS c ORDER BY c DESC"
    ).data()
    print("\nRelationship counts in Neo4j:")
    for row in result:
        print(f"  {row['rel']:<25} {row['c']}")


def main():
    load_dotenv()
    uri = os.getenv("NEO4J_URI")
    auth = (os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD"))

    graph = json.loads(GRAPH_PATH.read_text())
    print(f"Loaded {len(graph['nodes'])} nodes / {len(graph['relationships'])} relationships "
          f"from {GRAPH_PATH}")

    with GraphDatabase.driver(uri, auth=auth) as driver:
        driver.verify_connectivity()
        with driver.session() as session:
            print("\nCreating uniqueness constraints ...")
            create_constraints(session)

            print("\nLoading nodes ...")
            load_nodes(session, graph["nodes"])

            print("\nLoading relationships ...")
            load_relationships(session, graph["relationships"])

            print("\nCreating vector index on Functionality.embedding ...")
            create_vector_index(session, graph["embedding_dimensions"])

            verify(session)


if __name__ == "__main__":
    main()
