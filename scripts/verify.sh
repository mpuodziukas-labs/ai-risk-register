#!/bin/bash
# Verify: evaluate.py must report 32/32 and crosswalk_check.py must pass. Exit 0 or 1.
# --selftest plants bad crosswalk rows in a temporary copy and proves the check fails them.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"

verify() {
  local dir="$1" out
  out="$("$PY" "$dir/evaluate.py")" || { echo "FAIL evaluate.py exited nonzero" >&2; return 1; }
  if ! printf '%s\n' "$out" | tail -n 1 | grep -qx 'cases: 32/32 match'; then
    echo "FAIL evaluate.py did not print 'cases: 32/32 match'" >&2
    return 1
  fi
  echo "cases: 32/32 match"
  "$PY" "$dir/crosswalk_check.py" "$dir/crosswalk.tsv" --root "$dir" || return 1
}

selftest() {
  local pass=0 total=3
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir "$tmp/clean"
  cp -R "$ROOT/cases" "$ROOT/frameworks.json" "$ROOT/crosswalk.tsv" "$ROOT/crosswalk_check.py" "$tmp/clean/"
  local ok_url="https://artificialintelligenceact.eu/article/9/"

  if "$PY" "$tmp/clean/crosswalk_check.py" "$tmp/clean/crosswalk.tsv" --root "$tmp/clean" >/dev/null 2>&1; then
    pass=$((pass + 1)); echo "ok: clean copy exits 0"
  else
    echo "NOT ok: clean copy should exit 0"
  fi

  cp "$tmp/clean/crosswalk.tsv" "$tmp/bad_id.tsv"
  printf 'R99\tEU AI Act\tArt. 9(1)\tplanted unknown id\t%s\tGROUNDED\n' "$ok_url" >> "$tmp/bad_id.tsv"
  if ! "$PY" "$tmp/clean/crosswalk_check.py" "$tmp/bad_id.tsv" --root "$tmp/clean" >/dev/null 2>&1; then
    pass=$((pass + 1)); echo "ok: unknown register id exits 1"
  else
    echo "NOT ok: unknown register id should exit 1"
  fi

  cp "$tmp/clean/crosswalk.tsv" "$tmp/bad_word.tsv"
  printf 'R1\tEU AI Act\tArt. 9(1)\tplanted wording: certified\t%s\tGROUNDED\n' "$ok_url" >> "$tmp/bad_word.tsv"
  if ! "$PY" "$tmp/clean/crosswalk_check.py" "$tmp/bad_word.tsv" --root "$tmp/clean" >/dev/null 2>&1; then
    pass=$((pass + 1)); echo "ok: forbidden word exits 1"
  else
    echo "NOT ok: forbidden word should exit 1"
  fi

  echo "selftest $pass/$total"
  [ "$pass" -eq "$total" ]
}

case "${1:-}" in
  "") verify "$ROOT" ;;
  --selftest) selftest ;;
  *) echo "usage: scripts/verify.sh [--selftest]" >&2; exit 2 ;;
esac
