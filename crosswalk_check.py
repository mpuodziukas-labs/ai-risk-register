#!/usr/bin/env python3
"""Check crosswalk.tsv against the register. Exit 0 clean, 1 on any defect.

Usage: python3 crosswalk_check.py [crosswalk.tsv] [--root DIR]
Valid register ids: R1..R3 from frameworks.json, control ids from cases/*/profile.json,
evidence:<file> for files under cases/*/evidence, profile:<key> for keys in those profiles.
"""
import glob
import json
import os
import sys

HEADER = ["register_control_or_risk_id", "framework", "external_id",
          "external_title_paraphrase", "source_url", "status"]
FRAMEWORKS = {"ISO 27001:2022 Annex A", "SOC 2 TSC", "SR 11-7", "EU AI Act"}
STATUSES = {"GROUNDED", "INFERRED"}
PAYWALL = "id only, standard is paywalled"
FORBIDDEN = ("compliant", "certified", "attested")


def register_ids(root):
    ids = set()
    with open(os.path.join(root, "frameworks.json"), encoding="utf-8") as fh:
        for fam in json.load(fh)["families"].values():
            ids.add(fam["risk_id"])
    for path in glob.glob(os.path.join(root, "cases", "*", "profile.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                prof = json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(prof, dict):
            continue
        ids.update("profile:" + k for k in prof)
        controls = prof.get("controls")
        for c in controls if isinstance(controls, list) else []:
            if isinstance(c, dict) and isinstance(c.get("id"), str):
                ids.add(c["id"])
    for path in glob.glob(os.path.join(root, "cases", "*", "evidence", "*")):
        ids.add("evidence:" + os.path.basename(path))
    return ids


def check(tsv, root):
    """Return (row_count, list of error strings)."""
    errors = []
    with open(tsv, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if not lines or lines[0].split("\t") != HEADER:
        return 0, ["header must be: " + "\t".join(HEADER)]
    valid = register_ids(root)
    rows = [ln for ln in lines[1:] if ln.strip()]
    if not rows:
        errors.append("no data rows")
    for n, ln in enumerate(rows, start=2):
        cells = ln.split("\t")
        if len(cells) != len(HEADER):
            errors.append("line %d: expected %d columns, got %d" % (n, len(HEADER), len(cells)))
            continue
        rid, fw, ext, title, url, status = cells
        if rid not in valid:
            errors.append("line %d: unknown register id %r" % (n, rid))
        if fw not in FRAMEWORKS:
            errors.append("line %d: unknown framework %r" % (n, fw))
        if not ext.strip() or not title.strip():
            errors.append("line %d: empty external_id or title" % n)
        if status not in STATUSES:
            errors.append("line %d: invalid status %r" % (n, status))
        if not (url.startswith("https://") or (fw.startswith("ISO") and url == PAYWALL)):
            errors.append("line %d: missing or invalid source_url %r" % (n, url))
        if fw.startswith("ISO") and status != "INFERRED":
            errors.append("line %d: ISO rows are paywalled and must be INFERRED" % n)
        low = ln.lower()
        for word in FORBIDDEN:
            if word in low:
                errors.append("line %d: forbidden word %r" % (n, word))
    return len(rows), errors


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    root, tsv, args = here, None, argv[1:]
    while args:
        a = args.pop(0)
        if a == "--root" and args:
            root = args.pop(0)
        elif tsv is None and not a.startswith("--"):
            tsv = a
        else:
            print("usage: crosswalk_check.py [crosswalk.tsv] [--root DIR]", file=sys.stderr)
            return 2
    tsv = tsv or os.path.join(root, "crosswalk.tsv")
    try:
        count, errors = check(tsv, root)
    except (OSError, ValueError, KeyError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1
    for e in errors:
        print("FAIL " + e, file=sys.stderr)
    if errors:
        return 1
    print("crosswalk: %d rows ok" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
