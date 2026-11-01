"""The command line contract: exit codes, streams, output files, determinism."""
import json
import os
import re

import make_cases
from helpers import ASSESS, ROOT, case_paths, cli, materialize

NOW = make_cases.NOW


def test_pass_exit_zero_and_markdown_on_stdout():
    p, e = case_paths("clean_pass_high_risk")
    r = cli([p, e, "--now", NOW])
    assert r.returncode == 0 and r.stderr == ""
    assert r.stdout.startswith("# AI risk register: synthetic-screening-assistant")
    assert "## Crosswalk" in r.stdout and "MEASURE 2.11" in r.stdout and "LLM01:2025" in r.stdout


def test_refusal_exit_one_reasons_on_stderr_stdout_empty():
    p, e = case_paths("stale_evidence")
    r = cli([p, e, "--now", NOW])
    assert r.returncode == 1 and r.stdout == ""
    assert "REFUSED: 1 reason(s)" in r.stderr and "E_STALE: transcript.jsonl" in r.stderr


def test_bad_input_exit_two():
    p, e = case_paths("malformed_profile")
    r = cli([p, e, "--now", NOW])
    assert r.returncode == 2 and r.stderr.startswith("ERROR: cannot read profile")
    p, e = case_paths("bad_enum_profile")
    assert cli([p, e, "--now", NOW]).returncode == 2


def test_argument_errors_exit_two():
    p, e = case_paths("clean_pass_high_risk")
    assert cli([]).returncode == 2
    assert cli([p]).returncode == 2
    assert cli([p, e, "--now", "yesterday"]).returncode == 2
    assert cli([p, e, "--now", "2026-13-40T00:00:00Z"]).returncode == 2
    assert cli([p, os.path.join(e, "nope"), "--now", NOW]).returncode == 2
    assert cli([os.path.join(ROOT, "nope.json"), e, "--now", NOW]).returncode == 2
    assert cli([p, e, "--bogus"]).returncode == 2


def test_help_exits_zero():
    assert cli(["--help"]).returncode == 0


def test_out_dir_writes_register_files(tmp_path):
    p, e = case_paths("clean_pass_high_risk")
    out = str(tmp_path / "o")
    r = cli([p, e, "--now", NOW, "--out", out])
    assert r.returncode == 0 and sorted(os.listdir(out)) == ["register.json", "register.md"]
    data = json.load(open(os.path.join(out, "register.json")))
    assert data["status"] == "PASS" and len(data["risks"]) == 3
    assert all(r_["owner"] and r_["treatment"] for r_ in data["risks"])


def test_refusal_writes_refusal_json_and_no_register(tmp_path):
    p, e = case_paths("no_owner")
    out = str(tmp_path / "o")
    r = cli([p, e, "--now", NOW, "--out", out])
    assert r.returncode == 1 and os.listdir(out) == ["refusal.json"]
    assert json.load(open(os.path.join(out, "refusal.json")))["reasons"][0].startswith("R_NO_OWNER")


def test_two_runs_are_byte_identical(tmp_path):
    p, e = case_paths("injection_unsafe_completions")
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    cli([p, e, "--now", NOW, "--out", a])
    cli([p, e, "--now", NOW, "--out", b])
    for name in ("register.json", "register.md"):
        assert open(os.path.join(a, name), "rb").read() == open(os.path.join(b, name), "rb").read()


def test_every_case_exit_code_matches_its_expected_class():
    root = os.path.join(ROOT, "cases")
    for name in sorted(os.listdir(root)):
        want = json.load(open(os.path.join(root, name, "expected.json")))["expect"]
        code = {"PASS": 0, "REFUSE": 1, "BAD_INPUT": 2}[want.split(" ")[0]]
        p, e = case_paths(name)
        assert cli([p, e, "--now", NOW]).returncode == code, name


def test_no_dash_characters_or_banned_words_in_repo_text():
    banned = re.compile("|".join(["robust", "seamless", "leverage", "cutting-edge", "innovative",
                                  "comprehensive", "delve"]), re.IGNORECASE)
    for dirpath, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", ".mutants", "__pycache__", ".pytest_cache")]
        for f in files:
            if f in ("mutants.py",) or f.endswith(".pyc"):
                continue
            text = open(os.path.join(dirpath, f), encoding="utf-8").read()
            assert chr(0x2014) not in text and chr(0x2013) not in text, f
            if f not in ("test_cli.py",):
                assert not banned.search(text), (f, banned.search(text).group(0))


def test_source_has_no_network_imports():
    src = open(ASSESS, encoding="utf-8").read()
    for mod in ("socket", "urllib", "http", "requests", "subprocess"):
        assert not re.search(r"^\s*(import|from)\s+%s\b" % mod, src, re.M), mod
