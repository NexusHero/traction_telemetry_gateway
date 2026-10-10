#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <elf> [<elf>...]" >&2
  exit 2
fi

readelf_bin="${READELF:-readelf}"
overall=0

for bin in "$@"; do
  echo "== $bin"
  if ! header=$("$readelf_bin" -h "$bin" 2>/dev/null); then
    echo "  FAIL  not an ELF file readelf can parse"
    overall=1
    continue
  fi
  segments=$("$readelf_bin" -lW "$bin")
  dynamic=$("$readelf_bin" -dW "$bin")
  symbols=$("$readelf_bin" --dyn-syms -W "$bin")
  failed=0

  check() {
    local label="$1" ok="$2"
    if [[ "$ok" == yes ]]; then
      echo "  ok    $label"
    else
      echo "  FAIL  $label"
      failed=1
    fi
  }

  pie=no
  if grep -q 'Type:[[:space:]]*DYN' <<<"$header" && grep -q 'FLAGS_1.*PIE' <<<"$dynamic"; then
    pie=yes
  fi
  check "PIE (position-independent executable)" "$pie"

  relro=no
  if grep -q 'GNU_RELRO' <<<"$segments"; then relro=yes; fi
  check "RELRO segment" "$relro"

  now=no
  if grep -Eq '\(BIND_NOW\)|FLAGS_1.*NOW' <<<"$dynamic"; then now=yes; fi
  check "BIND_NOW (full RELRO)" "$now"

  nx=no
  stack_line=$(grep 'GNU_STACK' <<<"$segments" || true)
  if [[ -n "$stack_line" ]] && ! grep -q 'RWE' <<<"$stack_line"; then nx=yes; fi
  check "non-executable stack" "$nx"

  canary=no
  if grep -q '__stack_chk_fail' <<<"$symbols"; then canary=yes; fi
  check "stack protector (__stack_chk_fail imported)" "$canary"

  fortified=$(grep -oE '__[a-z0-9_]+_chk\b' <<<"$symbols" | grep -v '^__stack_chk$' | sort -u | tr '\n' ' ' || true)
  if [[ -n "$fortified" ]]; then
    echo "  info  FORTIFY_SOURCE active: ${fortified}"
  else
    echo "  info  no fortified libc calls found (not an error, see header)"
  fi

  if [[ "$failed" -ne 0 ]]; then
    overall=1
  fi
done

exit "$overall"
