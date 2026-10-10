#!/usr/bin/env bash
# Verifies the exploit mitigations CMakeLists.txt asks for on a built ELF.
#
#   scripts/check_hardening.sh build/ttg_server [more binaries...]
#
# The flags alone prove nothing: a toolchain can drop one without a word (an
# old linker ignoring -z now, a distro spec file overriding -fPIE, a flag
# passed to the wrong target). This reads what actually ended up in the binary,
# with readelf only, so it works for any architecture binutils can read -
# including the cross-built AArch64 binary on an x86-64 runner.
#
# Hard failures: PIE, full RELRO (GNU_RELRO + BIND_NOW), non-executable stack,
# stack canaries. FORTIFY is reported, not enforced: it only leaves a trace
# (__*_chk symbols) where the compiler could prove an object size, so a fully
# fortified binary can legitimately contain none.
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
  # --dyn-syms: a stripped binary has no .symtab, but the imports it resolves
  # at load time (__stack_chk_fail, __memcpy_chk) are always in .dynsym.
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

  # PIE: ET_DYN plus the PIE flag in DT_FLAGS_1 (a shared library is ET_DYN
  # too, so the type alone does not distinguish an executable).
  pie=no
  if grep -q 'Type:[[:space:]]*DYN' <<<"$header" && grep -q 'FLAGS_1.*PIE' <<<"$dynamic"; then
    pie=yes
  fi
  check "PIE (position-independent executable)" "$pie"

  relro=no
  if grep -q 'GNU_RELRO' <<<"$segments"; then relro=yes; fi
  check "RELRO segment" "$relro"

  # Full RELRO needs every symbol bound at load time; otherwise the GOT stays
  # writable for lazy binding and RELRO protects only part of it.
  now=no
  if grep -Eq '\(BIND_NOW\)|FLAGS_1.*NOW' <<<"$dynamic"; then now=yes; fi
  check "BIND_NOW (full RELRO)" "$now"

  # The GNU_STACK program header must exist (without it the kernel assumes an
  # executable stack) and its flags must be RW, not RWE.
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
