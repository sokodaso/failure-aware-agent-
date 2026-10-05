"""Neo4j connection from the project's .env."""

import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase

ROOT = Path(__file__).parent.parent


def get_driver() -> Driver:
    load_dotenv(ROOT / ".env")
    uri = (os.getenv("NEO4J_URI") or "").strip()
    user = (os.getenv("NEO4J_USERNAME") or "").strip()
    password = (os.getenv("NEO4J_PASSWORD") or "").strip()
    if not (uri and user and password):
        raise RuntimeError("NEO4J_URI / NEO4J_USERNAME / NEO4J_PASSWORD are not set in .env")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    driver.verify_connectivity()
    return driver
