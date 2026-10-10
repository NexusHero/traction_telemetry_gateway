<#
.SYNOPSIS
  Generate a CycloneDX SBOM for this project from the Conan dependency graph.

.DESCRIPTION
  Conan has no SBOM command in core; `conan sbom:cyclonedx` comes from the
  official conan-io/conan-extensions repo. This script installs that extension
  (and the cyclonedx library it needs) on first run, so a fresh checkout is one
  command away from an SBOM. Both installs are idempotent.

  build_tests=False drops gtest and --no-build-requires drops cmake, so the SBOM
  describes what actually ships in the image rather than what was needed to
  produce it.

.EXAMPLE
  .\scripts\sbom.ps1
  .\scripts\sbom.ps1 -Output C:\tmp\sbom.json -Scan
#>
[CmdletBinding()]
param(
    [string] $Output,
    [ValidateSet('Release', 'Debug', 'RelWithDebInfo', 'MinSizeRel')]
    [string] $BuildType = 'Release',
    [switch] $Scan
)

$ErrorActionPreference = 'Stop'

# Conan logs progress to stderr. Under Windows PowerShell 5.1 a native
# command's stderr becomes an ErrorRecord, which $ErrorActionPreference = 'Stop'
# then promotes to a terminating error - so a plain `conan ...` call aborts this
# script as soon as anyone pipes it (`.\sbom.ps1 2>&1 | tee log.txt`), even
# though conan exited 0. Every native call therefore goes through this helper,
# which judges success by exit code only.
function Invoke-Native {
    param(
        [Parameter(Mandatory)] [scriptblock] $Command,
        [Parameter(Mandatory)] [string] $ErrorMessage
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw $ErrorMessage }
}

# The extension must be importable by the interpreter that runs *conan*, which
# is not necessarily the python on PATH (venv, pipx, Store alias). So the probe
# is "does the command actually work" rather than an import check. cmd /c keeps
# the discarded output away from PowerShell's error stream entirely.
function Test-SbomCommand {
    cmd /c "conan sbom:cyclonedx -h >NUL 2>&1"
    return ($LASTEXITCODE -eq 0)
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Output) { $Output = Join-Path $repoRoot 'build\sbom.cdx.json' }

if (-not (Get-Command conan -ErrorAction SilentlyContinue)) {
    throw 'conan not found. pip install "conan>=2.0"'
}

$conanHome = Invoke-Native { conan config home } 'conan config home failed'
# Pinned by commit - see scripts/sbom.sh for the reasoning. Keep both in sync.
$extensionsCommit = 'd2c9d79e5c6293bee21b3a21f60c34ec0a88f6b7'
$refMarker = Join-Path $conanHome 'extensions\.conan-extensions-commit'
$installed = if (Test-Path $refMarker) { (Get-Content $refMarker -Raw).Trim() } else { '' }

if ($installed -ne $extensionsCommit) {
    Write-Host ">> installing conan sbom extension @ $($extensionsCommit.Substring(0, 12))"
    Invoke-Native {
        conan config install "https://github.com/conan-io/conan-extensions/archive/$extensionsCommit.zip" `
            -sf "conan-extensions-$extensionsCommit"
    } 'conan config install failed'
    Set-Content -Path $refMarker -Value $extensionsCommit -NoNewline
}

if (-not (Test-SbomCommand)) {
    Write-Host '>> installing cyclonedx-python-lib (first run only)'
    Invoke-Native {
        python -m pip install --quiet 'cyclonedx-python-lib>=5.0.0,<6'
    } 'pip install cyclonedx-python-lib failed'
    if (-not (Test-SbomCommand)) {
        throw ('"conan sbom:cyclonedx" is still unusable. Install the library ' +
               'into the environment that provides conan: ' +
               'pip install "cyclonedx-python-lib>=5.0.0,<6"')
    }
}

$outDir = Split-Path -Parent $Output
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

# 1.4_json is the newest format this extension emits. The default is "text",
# which the extension itself then rejects - so --format is not optional.
# "&:build_tests=False" scopes the option to this package; unscoped is ambiguous
# in Conan 2 and only warns today.
Invoke-Native {
    conan sbom:cyclonedx $repoRoot `
        --format 1.4_json `
        --out-file $Output `
        --no-build-requires `
        -s "build_type=$BuildType" `
        -o '&:build_tests=False'
} 'conan sbom:cyclonedx failed'

# The extension's output falls short of BSI TR-03183-2 (CycloneDX 1.4, no
# hashes, "Conan" as every component's maker). Enriched in place, so no SBOM
# leaves this script in the weaker form. Needs Python >= 3.11 (tomllib).
Invoke-Native {
    python (Join-Path $repoRoot 'scripts/sbom_enrich.py') --sbom $Output --build-type $BuildType
} 'sbom_enrich.py failed'

Write-Host ">> wrote $Output"

if ($Scan) {
    if (-not (Get-Command grype -ErrorAction SilentlyContinue)) {
        throw 'grype not found. see https://github.com/anchore/grype'
    }
    # Heads-up: the extension emits package URLs but no CPEs, and grype matches
    # C/C++ packages on CPEs, so a clean report here is weak evidence. The CVE
    # gate that actually bites is `conan audit scan` in
    # .github/workflows/supply-chain.yml, which matches on Conan references.
    Write-Host ">> grype sbom:$Output (see comment above about CPE matching)"
    Invoke-Native { grype "sbom:$Output" } 'grype reported findings or failed'
}
