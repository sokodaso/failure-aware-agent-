"""Score completions with CodeGuard+'s own CodeQL and unit-test code. Run with the evaluator venv:

eval/.venv-cg/bin/python scripts/cg_score.py OUT_ROOT VUL_TYPE SCENARIO

OUT_ROOT uses CodeGuard+'s layout: OUT_ROOT/none/base/<vul_type>/<scenario>/deduplicated/NN.<ext> (+ Makefile for C)
and stat.json beside `deduplicated`. Writes score.json there: per file, functional, CodeQL-secure and sec-pass, plus
every CodeQL finding and how many source files the CodeQL database actually extracted.

This mirrors codeql_eval.eval_single but keeps the database long enough to count extracted files: an extraction
that silently fails gives an empty result, which would otherwise score every sample as secure.
Security is CodeQL only (no SonarQube), as in docs/eval_plan.md.
"""

import csv
import json
import os
import shutil
import subprocess
import sys
import types
import zipfile
from pathlib import Path

CG = Path(__file__).resolve().parent.parent / "eval" / "CodeGuardPlus"
VENV_BIN = Path(sys.executable).parent

# Queries that do not compile in the codeql-repo checkout. CodeGuard+'s patched ArithmeticTainted.ql imports the
# legacy semmle.code.cpp.security.TaintTracking, which the repo at codeql-cli-2.17.5 no longer has but the pinned
# cpp-all@0.7.1 pack (setup_codeql.sh) does. Same query text, in a local pack depending on cpp-all 0.7.1.
QUERY_OVERRIDES = {
    "~/codeql/codeql-repo/cpp/ql/src/Security/CWE/CWE-190/ArithmeticTainted.ql":
        "~/codeql/codeguard-legacy-cpp/ArithmeticTainted.ql",
}

sys.modules.setdefault("torch", types.ModuleType("torch"))  # imported by codeql_eval, never used there
sys.path.insert(0, str(CG))
import codeql_eval  # noqa: E402
import correctness_eval  # noqa: E402


def extracted_files(db: Path, ext: str) -> list[str]:
    src = db / "src.zip"
    if not src.exists():
        return []
    with zipfile.ZipFile(src) as z:
        return sorted(n for n in z.namelist() if n.endswith("." + ext))


def score(out_root: Path, vul_type: str, scenario: str) -> dict:
    out_root = out_root.resolve()
    s_out = out_root / "none" / "base" / vul_type / scenario
    src_dir = s_out / "deduplicated"
    info = json.loads((CG / "data" / "base" / vul_type / scenario / "info.json").read_text())
    if not info.get("check_ql"):
        raise SystemExit(f"{vul_type}/{scenario} has no CodeQL query; its security cannot be scored")
    info["check_ql"] = QUERY_OVERRIDES.get(info["check_ql"], info["check_ql"])
    ext = info["language"]
    fnames =sorted(f for f in os.listdir(src_dir) if f.endswith(ext) and f not in ("temp.c", "sales.c"))
    if not fnames:
        raise SystemExit(f"no .{ext} files in {src_dir}")

    cwd = os.getcwd()
    os.chdir(CG)  # the stock code uses paths relative to the repo
    os.environ["PATH"] = f"{VENV_BIN}{os.pathsep}{os.environ['PATH']}"  # check_functional runs `python`
    try:
        csv_path, db = s_out / "codeql.csv", s_out / "codeql_db"
        codeql_eval.codeql_create_db(info, str(src_dir), str(db))
        extracted = extracted_files(db, ext)
        codeql_eval.codeql_analyze(info, str(db), str(csv_path))
        if not csv_path.exists():
            raise RuntimeError(f"CodeQL produced no results file for {vul_type}/{scenario}")
        if vul_type == "cwe-078" and ext == "py":
            codeql_eval.filter_cwe78_fps(str(s_out))
        shutil.rmtree(db, ignore_errors=True)
        correctness_eval.check_functional(vul_type, scenario, str(src_dir))
    finally:
        os.chdir(cwd)

    findings = []
    with csv_path.open() as f:
        for row in csv.reader(f):
            if len(row) >= 5:
                findings.append({"rule": row[0], "description": row[1], "severity": row[2], "message": row[3],
                                 "file": row[-5].replace("/", ""), "start_line": int(row[-4]), "end_line": int(row[-2])})
    stat = json.loads((s_out / "stat.json").read_text())
    flagged = {x["file"] for x in findings}
    files = {}
    for fn in fnames:
        functional = bool(stat.get(fn, {}).get("functional", False))
        secure = fn not in flagged
        files[fn] = {"functional": functional, "codeql_secure": secure, "sec_pass": functional and secure,
                     "findings": [x for x in findings if x["file"] == fn]}
    result = {"vul_type": vul_type, "scenario": scenario, "check_ql": info["check_ql"],
              "extracted_files": extracted, "extraction_ok": set(fnames) <= {Path(n).name for n in extracted},
              "n": len(fnames), "functional": sum(v["functional"] for v in files.values()),
              "codeql_secure": sum(v["codeql_secure"] for v in files.values()),
              "sec_pass": sum(v["sec_pass"] for v in files.values()), "files": files}
    (s_out / "score.json").write_text(json.dumps(result, indent=1))
    return result


def layout(out_root: Path, vul_type: str, scenario: str, completions: list[str] | dict[str, str]) -> Path:
    """Write full programs into CodeGuard+'s layout. A list is numbered 00, 01, ...; a dict maps a sample number
    ("03") to its program, so samples keep their own numbers. Returns the scenario output dir."""
    info = json.loads((CG / "data" / "base" / vul_type / scenario / "info.json").read_text())
    ext = info["language"]
    s_out = out_root / "none" / "base" / vul_type / scenario
    src_dir = s_out / "deduplicated"
    if s_out.exists():
        shutil.rmtree(s_out)
    src_dir.mkdir(parents=True)
    stat = {}
    items = completions.items() if isinstance(completions, dict) else ((f"{i:02d}", c) for i, c in enumerate(completions))
    for num, code in items:
        fn = f"{num}.{ext}"
        (src_dir / fn).write_text(code)
        stat[fn] = {"num": 1}
    if ext in ("c", "cpp"):
        shutil.copy2(CG / "inference" / "makefiles" / ext / "Makefile", src_dir)
    (s_out / "stat.json").write_text(json.dumps(stat, indent=2))
    return s_out


if __name__ == "__main__":
    r = score(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    print(json.dumps({k: v for k, v in r.items() if k != "files"}, indent=1))
    for fn, v in r["files"].items():
        print(fn, "functional" if v["functional"] else "NOT functional", "| secure" if v["codeql_secure"] else "| FLAGGED",
              [x["rule"] for x in v["findings"]])
