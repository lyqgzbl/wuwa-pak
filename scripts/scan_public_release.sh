#!/usr/bin/env bash
set -euo pipefail

target="${1:-.}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
denylist="$script_dir/denylist_paths.txt"
terms="$script_dir/sensitive_terms.txt"

if [ ! -e "$target" ]; then
  printf 'scan target does not exist: %s\n' "$target" >&2
  exit 2
fi

failed=0

while IFS= read -r file; do
  while IFS= read -r pattern || [ -n "$pattern" ]; do
    [[ -z "$pattern" || "$pattern" == \#* ]] && continue
    if [[ "$file" == $pattern ]]; then
      printf 'blocked: denied public-bound path: %s (matched %s)\n' "$file" "$pattern" >&2
      failed=1
    fi
  done < "$denylist"
done < <(rg --files "$target")

while IFS= read -r file; do
  [ -f "$file" ] || continue
  case "$file" in
    scripts/denylist_paths.txt|*/scripts/denylist_paths.txt|scripts/sensitive_terms.txt|*/scripts/sensitive_terms.txt)
      continue
      ;;
    *.html|*.lock|LICENSE|*/LICENSE|NOTICE|*/NOTICE|README.md|*/README.md)
      continue
      ;;
  esac
  while IFS= read -r term || [ -n "$term" ]; do
    [[ -z "$term" || "$term" == \#* ]] && continue
    if rg -n --hidden --glob '!*.html' --glob '!*.lock' --glob '!README.md' -- "$term" "$file"; then
      printf 'blocked: sensitive term found in public-bound file: %s\n' "$file" >&2
      failed=1
    fi
  done < "$terms"
done < <(rg --files "$target")

if [ "$failed" -ne 0 ]; then
  exit 1
fi
printf 'public release scan passed: %s\n' "$target"
