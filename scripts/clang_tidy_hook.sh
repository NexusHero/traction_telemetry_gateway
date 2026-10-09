#!/usr/bin/env bash
#
# pre-commit hook wrapper for clang-tidy.
#
# clang-tidy cannot analyse a translation unit without knowing how it is
# compiled, and that information lives in a compilation database produced by
# CMake. Rather than fail on a fresh clone that has never been configured, this
# wrapper degrades to a no-op with a hint. CI always has the database, so the
# check is never silently skipped where it matters.
#
# Checks come from .clang-tidy in the repo root - not from a -checks= flag -
# so hooks, CI and editors all see the same rule set.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Honour an explicit build directory, else try the conventional ones.
if [[ -n "${TTG_BUILD_DIR:-}" ]]; then
  candidates=("$TTG_BUILD_DIR")
else
  candidates=("$repo_root/build" "$repo_root/build-debug" "$repo_root/cmake-build-debug")
fi

build_dir=""
for candidate in "${candidates[@]}"; do
  if [[ -f "$candidate/compile_commands.json" ]]; then
    build_dir="$candidate"
    break
  fi
done

if [[ -z "$build_dir" ]]; then
  echo "clang-tidy: no compile_commands.json found - skipping."
  echo "  To enable this hook, configure a build tree with:"
  echo "    cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \\"
  echo "      -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake"
  echo "  (or point TTG_BUILD_DIR at an existing one)"
  exit 0
fi

command -v clang-tidy >/dev/null || {
  echo "clang-tidy: not installed - skipping. (apt install clang-tidy)"
  exit 0
}

# Headers have no entry of their own in the compilation database; .clang-tidy
# sets HeaderFilterRegex so they are still analysed via the .cpp that includes
# them. Passing a header directly would just produce a "not found in
# compilation database" error, so filter to sources here.
sources=()
for arg in "$@"; do
  [[ "$arg" == *.cpp ]] && sources+=("$arg")
done

if [[ ${#sources[@]} -eq 0 ]]; then
  exit 0
fi

echo "clang-tidy: analysing ${#sources[@]} file(s) against $build_dir"
exec clang-tidy -p "$build_dir" --quiet "${sources[@]}"
