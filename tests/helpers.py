"""Shared helpers. Paths resolve from this file, so a mutant copy of the repo tests itself."""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import assess  # noqa: E402
import make_cases  # noqa: E402

NOW = assess.parse_ts(make_cases.NOW)
ASSESS = os.path.join(ROOT, "assess.py")
CASES = os.path.join(ROOT, "cases")


def materialize(case, tmp_path, name="bundle"):
    """Write a make_cases.Case under tmp_path. Returns (profile_path, evidence_dir)."""
    base = str(tmp_path / name)
    os.makedirs(base)
    case.write(os.path.join(base, "evidence"))
    ppath = os.path.join(base, "profile.json")
    with open(ppath, "w", encoding="utf-8") as fh:
        fh.write(case.profile_text if case.profile_text is not None else json.dumps(case.profile))
    return ppath, os.path.join(base, "evidence")


def result_of(case, tmp_path, name="bundle"):
    p, e = materialize(case, tmp_path, name)
    return assess.run(p, e, NOW)


def codes(result):
    return sorted({r.split(":", 1)[0] for r in result.get("reasons", [])})


def cli(args, **kw):
    return subprocess.run([sys.executable, ASSESS] + list(args), capture_output=True, text=True, **kw)


def case_paths(name):
    return (os.path.join(CASES, name, "profile.json"), os.path.join(CASES, name, "evidence"))
