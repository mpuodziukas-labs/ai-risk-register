#!/usr/bin/env python3
"""Run assess.py over every case in cases/ and compare with expected.json.

Case string: PASS <tier> bias=<L>x<I>><L>x<I> leak=... inj=...   (inherent > residual)
             REFUSE <sorted reason codes>   |   BAD_INPUT
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
sys.path.insert(0, HERE)
import assess  # noqa: E402

SHORT = (("bias", "model_bias"), ("leak", "data_leakage"), ("inj", "prompt_injection"))


def summarize(result):
    if result["status"] == "REFUSED":
        codes = sorted({r.split(":", 1)[0] for r in result["reasons"]})
        return "REFUSE " + ",".join(codes)
    by = {r["family"]: r for r in result["risks"]}
    parts = []
    for short, fam in SHORT:
        r = by[fam]
        parts.append("%s=%dx%d>%dx%d" % (short, r["inherent"]["likelihood"], r["impact"],
                                         r["residual"]["likelihood"], r["impact"]))
    return "PASS %s %s" % (result["tier"]["tier"], " ".join(parts))


def run_case(name):
    folder = os.path.join(CASES, name)
    try:
        with open(os.path.join(folder, "expected.json"), encoding="utf-8") as fh:
            expected = json.load(fh)
        want, now = expected["expect"], assess.parse_ts(expected["now"])
    except (OSError, ValueError, KeyError):
        return "unreadable expected.json", "ERROR"
    try:
        got = summarize(assess.run(os.path.join(folder, "profile.json"), os.path.join(folder, "evidence"), now))
    except assess.BadInput:
        got = "BAD_INPUT"
    except Exception as exc:  # a crash is a mismatch, never a pass
        got = "ERROR " + type(exc).__name__
    return want, got


def main():
    names = sorted(n for n in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, n)))
    matched, rows = 0, []
    print("| case | expected | got | match |")
    print("|---|---|---|---|")
    for n in names:
        want, got = run_case(n)
        ok = want == got
        matched += ok
        rows.append({"case": n, "expected": want, "got": got, "match": ok})
        print("| %s | %s | %s | %s |" % (n, want, got, "yes" if ok else "NO"))
    with open(os.path.join(HERE, "PROOF.json"), "w", encoding="utf-8") as fh:
        json.dump({"matched": matched, "total": len(names), "cases": rows}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print()
    print("cases: %d/%d match" % (matched, len(names)))
    return 0 if names and matched == len(names) else 1


if __name__ == "__main__":
    sys.exit(main())
