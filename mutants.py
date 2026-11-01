#!/usr/bin/env python3
"""Mutation check. Each mutant changes one spot in assess.py inside a throwaway copy of the
repo under .mutants/. evaluate.py and the pytest suite then run on the copy. A mutant is
killed when either exits non-zero. Copies are left in place. Last line: mutants: K/K killed"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
A = "assess.py"

MUTANTS = [
    ("skip_staleness_check", A, "elif self.now - recorded > timedelta(days=max_age):", "elif False:"),
    ("staleness_boundary_off_by_one", A, "> timedelta(days=max_age)", ">= timedelta(days=max_age)"),
    ("future_recorded_at_accepted", A, "if recorded > self.now:", "if False:"),
    ("accept_bad_sha256", A, "if hashlib.sha256(raw).hexdigest() != sha.lower():", "if False:"),
    ("symlink_evidence_followed", A, "if os.path.islink(path):", "if False:"),
    ("duplicate_keys_accepted", A, "if len(keys) != len(set(keys)):", "if False:"),
    ("nan_accepted", A, ", parse_constant=_const", ""),
    ("four_fifths_strict", A, '"passes_four_fifths": min_di >= FOUR_FIFTHS,', '"passes_four_fifths": min_di > FOUR_FIFTHS,'),
    ("report_tolerance_widened", A, "tol = Fraction(1, 2000)", "tol = Fraction(1, 20)"),
    ("leakage_contradiction_ignored", A,
     'if rep["findings"] != m["findings_total"] or rep["canary_hits"] != m["canary_hits"]:', "if False:"),
    ("control_without_evidence_allowed", A, 'if not c["evidence_files"]:', "if False:"),
    ("control_fail_result_not_flagged", A, 'if result == "fail":', "if False:"),
    ("owner_not_required", A, 'if not _nonempty_str(row.get("owner")):', "if False:"),
    ("treatment_not_required", A, 'if row.get("treatment") not in TREATMENTS:', "if False:"),
    ("accept_appetite_dropped", A, 'if r["treatment"] == "accept" and', 'if False and'),
    ("accept_appetite_boundary", A, 'r["residual"]["score"] > ACCEPT_MAX_SCORE', 'r["residual"]["score"] >= ACCEPT_MAX_SCORE'),
    ("prohibited_tier_not_refused", A, 'if tier["tier"] == "prohibited":', "if False:"),
    ("luhn_check_dropped", A, "if 13 <= len(digits) <= 16 and luhn_ok(digits):", "if 13 <= len(digits) <= 16:"),
    ("canary_scan_dropped", A, 'if c in row["text"]:', "if False:"),
    ("unplanted_canary_accepted", A, "if missing:", "if False:"),
    ("reduction_cap_raised", A, "MAX_REDUCTION = 2", "MAX_REDUCTION = 3"),
    ("residual_floor_removed", A, "residual_l = max(1, inherent_l - reduction)", "residual_l = inherent_l - reduction"),
    ("obligation_flag_always_true", A, 'high = tier["tier"] == "high_risk"', "high = True"),
    ("small_groups_accepted", A, "MIN_GROUP_ROWS = 10", "MIN_GROUP_ROWS = 1"),
]


def run_checks(root):
    codes = []
    for cmd in (["evaluate.py"], ["-m", "pytest", "-q", "-p", "no:cacheprovider", "-x"]):
        r = subprocess.run([sys.executable] + cmd, cwd=root, capture_output=True, text=True)
        codes.append(r.returncode)
    return codes


def make_copy(base):
    root = tempfile.mkdtemp(dir=base)
    shutil.copytree(HERE, root, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".mutants", "__pycache__", ".git", ".pytest_cache"))
    return root


def main():
    base = os.path.join(HERE, ".mutants")
    os.makedirs(base, exist_ok=True)
    clean = run_checks(HERE)
    print("control: evaluate rc=%d, pytest rc=%d" % tuple(clean))
    if any(clean):
        print("mutants: 0/%d killed" % len(MUTANTS))
        return 1
    killed = 0
    for name, fname, old, new in MUTANTS:
        with open(os.path.join(HERE, fname), encoding="utf-8") as fh:
            source = fh.read()
        if source.count(old) != 1:
            print("INVALID %s (spot found %d times)" % (name, source.count(old)))
            continue
        mutated = source.replace(old, new)
        try:
            compile(mutated, fname, "exec")
        except SyntaxError:
            print("INVALID %s (does not compile)" % name)
            continue
        root = make_copy(base)
        with open(os.path.join(root, fname), "w", encoding="utf-8") as fh:
            fh.write(mutated)
        if any(c != 0 for c in run_checks(root)):
            killed += 1
            print("KILLED %s" % name)
        else:
            print("SURVIVED %s" % name)
    print("mutants: %d/%d killed" % (killed, len(MUTANTS)))
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
