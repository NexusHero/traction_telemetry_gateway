#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: ./scripts/sbom.sh [-o <path>] [-t <build-type>] [--scan]

  -o, --output     output path (default: build/sbom.cdx.json)
  -t, --build-type Conan build_type (default: Release)
      --scan       also run grype against the result
EOF
}

EXTENSIONS_COMMIT="d2c9d79e5c6293bee21b3a21f60c34ec0a88f6b7"
EXTENSIONS_ARCHIVE="https://github.com/conan-io/conan-extensions/archive/${EXTENSIONS_COMMIT}.zip"
CYCLONEDX_LIB="cyclonedx-python-lib>=5.0.0,<6"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$repo_root/build/sbom.cdx.json"
build_type="Release"
scan=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)     output="$2"; shift 2 ;;
    -t|--build-type) build_type="$2"; shift 2 ;;
    --scan)          scan=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v conan >/dev/null || {
  echo "error: conan not found. pip install \"conan>=2.0\"" >&2; exit 1
}

sbom_usable() { conan sbom:cyclonedx -h >/dev/null 2>&1; }

pip_install_cyclonedx() {
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "pass" >/dev/null 2>&1; then
      "$candidate" -m pip install --quiet "$CYCLONEDX_LIB" && return 0
    fi
  done
  return 1
}

ref_marker="$(conan config home)/extensions/.conan-extensions-commit"
if [[ "$(cat "$ref_marker" 2>/dev/null)" != "$EXTENSIONS_COMMIT" ]]; then
  echo ">> installing conan sbom extension @ ${EXTENSIONS_COMMIT:0:12}"
  conan config install "$EXTENSIONS_ARCHIVE" -sf "conan-extensions-${EXTENSIONS_COMMIT}"
  echo "$EXTENSIONS_COMMIT" > "$ref_marker"
fi

if ! sbom_usable; then
  echo ">> installing $CYCLONEDX_LIB (first run only)"
  pip_install_cyclonedx || true
  if ! sbom_usable; then
    echo "error: 'conan sbom:cyclonedx' is still unusable." >&2
    echo "       Install the library into the environment that provides conan:" >&2
    echo "       pip install \"$CYCLONEDX_LIB\"" >&2
    exit 1
  fi
fi

mkdir -p "$(dirname "$output")"

conan sbom:cyclonedx "$repo_root" \
  --format 1.4_json \
  --out-file "$output" \
  --no-build-requires \
  -s "build_type=$build_type" \
  -o "&:build_tests=False"

python3 "$repo_root/scripts/sbom_enrich.py" --sbom "$output" --build-type "$build_type"

echo ">> wrote $output"

if [[ $scan -eq 1 ]]; then
  command -v grype >/dev/null || {
    echo "error: grype not found. see https://github.com/anchore/grype" >&2; exit 1
  }
  echo ">> grype sbom:$output"
  grype "sbom:$output"
fi
