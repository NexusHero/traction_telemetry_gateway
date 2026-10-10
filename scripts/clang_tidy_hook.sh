#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

sources=()
for arg in "$@"; do
  [[ "$arg" == *.cpp ]] && sources+=("$arg")
done

if [[ ${#sources[@]} -eq 0 ]]; then
  exit 0
fi

echo "clang-tidy: analysing ${#sources[@]} file(s) against $build_dir"
exec clang-tidy -p "$build_dir" --quiet "${sources[@]}"
