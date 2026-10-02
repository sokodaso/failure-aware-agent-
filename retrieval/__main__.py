"""python -m retrieval "write a function that extracts a tar archive" --language python --api tarfile.open"""

import argparse
import json
from dataclasses import asdict

from .compare import annotate_api_overlap, rank_cwes
from .context import attach_cwe_context
from .db import get_driver
from .search import Embedder, search_functionality


def retrieve(driver, embedder, query, language=None, expected_apis=(), k=5, top_cwes=5):
    """Functionality search -> local API comparison -> ranked CWEs with context."""
    hits = search_functionality(driver, embedder, query, language, k)
    annotate_api_overlap(hits, list(expected_apis))
    candidates = rank_cwes(hits, top_cwes)
    attach_cwe_context(driver, candidates)
    return hits, candidates


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query", help="natural-language functionality description")
    ap.add_argument("--language", help="python, c, cpp, ... (c and cpp match each other)")
    ap.add_argument("--api", action="append", default=[], help="expected API call (repeatable)")
    ap.add_argument("-k", type=int, default=5, help="functionality hits to keep")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    driver = get_driver()
    try:
        hits, cands = retrieve(driver, Embedder(), args.query, args.language, args.api, args.k)
    finally:
        driver.close()

    if args.json:
        print(json.dumps({"hits": [asdict(h) for h in hits], "cwes": [asdict(c) for c in cands]}, indent=2))
        return
    print("FUNCTIONALITY HITS")
    for h in hits:
        roles = ", ".join(f"{v.role[:4]}:{','.join(v.cwes) or '-'}" for v in h.versions)
        print(f"  {h.similarity:.3f}  {h.text[:90]}\n         [{roles}]")
    print("\nCWE CANDIDATES")
    for c in cands:
        best = c.evidence[0]
        print(f"  {c.cwe:<8} {c.score:.3f}  {c.name}  ({len(c.evidence)} versions, best sim {best.similarity:.2f}, api {best.api_overlap:.2f})")
        if best.fix and best.fix.cause:
            print(f"           fix: {best.fix.cause[:140]}")


if __name__ == "__main__":
    main()
