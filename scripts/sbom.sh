#!/usr/bin/env bash
#
# Generate a CycloneDX SBOM for this project from the Conan dependency graph.
#
#   ./scripts/sbom.sh                     # -> build/sbom.cdx.json
#   ./scripts/sbom.sh -o /tmp/sbom.json   # pick the output path
#   ./scripts/sbom.sh --scan              # also run grype against the result
#
# Conan has no SBOM command in core; `conan sbom:cyclonedx` comes from the
# official conan-io/conan-extensions repo. This script installs that extension
# (and the cyclonedx library it needs) on first run, so a fresh checkout is one
# command away from an SBOM. Both installs are idempotent.
#
# Note on options: build_tests=False drops gtest, and --no-build-requires drops
# cmake, so the SBOM describes what actually ships in the image rather than what
# was needed to produce it.
set -euo pipefail

# Pinned by commit. The extension is code that runs inside the SBOM job and
# shapes the SBOM that gets attested, so it is treated like any other
# dependency: a fixed revision, bumped deliberately - never "whatever the
# default branch holds today". The archive of a commit is addressed by its SHA.
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
    -h|--help)       sed -n '3,9p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v conan >/dev/null || {
  echo "error: conan not found. pip install \"conan>=2.0\"" >&2; exit 1
}

# The extension must be importable by the interpreter that runs *conan*, which
# is not necessarily the python3 on PATH (venv, pipx, distro package). So the
# probe is "does the command actually work", and only the repair path needs an
# interpreter of its own.
sbom_usable() { conan sbom:cyclonedx -h >/dev/null 2>&1; }

pip_install_cyclonedx() {
  # command -v is not enough: on Windows a python3 App Execution Alias resolves
  # but fails to run, so each candidate is tested before use.
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "pass" >/dev/null 2>&1; then
      "$candidate" -m pip install --quiet "$CYCLONEDX_LIB" && return 0
    fi
  done
  return 1
}

# The marker records which commit is installed, so a Conan home holding a
# different revision (an older run, a manual install) is brought to the pin.
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

# 1.4_json is the newest format this extension emits. The default is "text",
# which the extension itself then rejects - so -f is not optional.
conan sbom:cyclonedx "$repo_root" \
  --format 1.4_json \
  --out-file "$output" \
  --no-build-requires \
  -s "build_type=$build_type" \
  -o "&:build_tests=False"

# The extension's output falls short of BSI TR-03183-2 (CycloneDX 1.4, no
# hashes, "Conan" as every component's maker). Enriched in place, so no SBOM
# leaves this script in the weaker form. Needs Python >= 3.11 (tomllib).
python3 "$repo_root/scripts/sbom_enrich.py" --sbom "$output" --build-type "$build_type"

echo ">> wrote $output"

if [[ $scan -eq 1 ]]; then
  command -v grype >/dev/null || {
    echo "error: grype not found. see https://github.com/anchore/grype" >&2; exit 1
  }
  # Heads-up: the extension emits package URLs but no CPEs, and grype matches
  # C/C++ packages on CPEs. A clean report here is therefore weak evidence -
  # the CVE gate that actually bites runs in .github/workflows/supply-chain.yml.
  echo ">> grype sbom:$output (see comment above about CPE matching)"
  grype "sbom:$output"
fi
