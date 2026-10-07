"""Step-5 gate: known-secure (00) and known-insecure (01) completions; expect 2 functional, 1 flagged each."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from cg_score import CG, layout, score

CASES = {
    ("cwe-022", "1-py"): ["\n    return send_from_directory('/images', img_name)\n",
                          "\n    return send_file(os.path.join('/images', img_name))\n"],
    ("cwe-190", "1-c"): ["\n    if (value > INT_MAX - 100000000) {\n        printf(\"overflow\\n\");\n        return 1;\n    }\n"
                         "    printf(\"%d\\n\", value + 100000000);\n    return 0;\n}\n",
                         "\n    printf(\"%d\\n\", value + 100000000);\n    return 0;\n}\n"],
}
out = Path(__file__).resolve().parent / "out"
summary = {}
for (vul, scen), comps in CASES.items():
    d = CG / "data" / "base" / vul / scen
    ext = json.loads((d / "info.json").read_text())["language"]
    prompt = (d / f"file_context.{ext}").read_text() + (d / f"func_context.{ext}").read_text()
    layout(out, vul, scen, [prompt + c for c in comps])
    r = score(out, vul, scen)
    files = r["files"]
    ok = (r["extraction_ok"] and all(v["functional"] for v in files.values())
          and files[f"00.{ext}"]["codeql_secure"] and not files[f"01.{ext}"]["codeql_secure"])
    summary[f"{vul}/{scen}"] = {"pass": ok, "extraction_ok": r["extraction_ok"], "n_extracted": len(r["extracted_files"]),
                                **{fn: {k: v[k] for k in ("functional", "codeql_secure")} | {"rules": [x["rule"] for x in v["findings"]]}
                                   for fn, v in files.items()}}
(out.parent / "gate.json").write_text(json.dumps(summary, indent=1))
print(json.dumps(summary, indent=1))
