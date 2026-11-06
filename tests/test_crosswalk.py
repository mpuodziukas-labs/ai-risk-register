"""crosswalk_check.py contract, tested through the command line."""
import os
import subprocess
import sys

from helpers import ROOT

CHECK = os.path.join(ROOT, "crosswalk_check.py")
TSV = os.path.join(ROOT, "crosswalk.tsv")
GOOD = ("R1\tEU AI Act\tArt. 9(2)(a)\tidentify risks\t"
        "https://artificialintelligenceact.eu/article/9/\tGROUNDED")


def run(tsv):
    return subprocess.run([sys.executable, CHECK, str(tsv)], capture_output=True, text=True)


def write(tmp_path, *rows):
    header = open(TSV, encoding="utf-8").read().splitlines()[0]
    p = tmp_path / "x.tsv"
    p.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")
    return p


def test_shipped_crosswalk_is_clean_and_nonempty():
    r = run(TSV)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("crosswalk: ") and not r.stdout.startswith("crosswalk: 0 ")


def test_single_good_row_passes(tmp_path):
    assert run(write(tmp_path, GOOD)).returncode == 0


def test_unknown_register_id_fails(tmp_path):
    r = run(write(tmp_path, GOOD.replace("R1", "R99", 1)))
    assert r.returncode == 1 and "unknown register id 'R99'" in r.stderr


def test_missing_source_url_fails(tmp_path):
    r = run(write(tmp_path, GOOD.replace("https://artificialintelligenceact.eu/article/9/", "")))
    assert r.returncode == 1 and "source_url" in r.stderr


def test_bad_status_fails(tmp_path):
    r = run(write(tmp_path, GOOD.replace("GROUNDED", "PROBABLY")))
    assert r.returncode == 1 and "invalid status" in r.stderr


def test_forbidden_words_fail(tmp_path):
    for word in ("compliant", "Certified", "attested"):
        r = run(write(tmp_path, GOOD.replace("identify risks", "is " + word)))
        assert r.returncode == 1 and "forbidden word" in r.stderr, word


def test_iso_row_cannot_be_grounded(tmp_path):
    row = "R2\tISO 27001:2022 Annex A\tA.8.12\tleak prevention\tid only, standard is paywalled\tGROUNDED"
    assert run(write(tmp_path, row)).returncode == 1


def test_empty_crosswalk_is_not_a_pass(tmp_path):
    r = run(write(tmp_path))
    assert r.returncode == 1 and "no data rows" in r.stderr


def test_bad_header_fails(tmp_path):
    p = tmp_path / "h.tsv"
    p.write_text("a\tb\n" + GOOD + "\n", encoding="utf-8")
    assert run(p).returncode == 1
