#!/usr/bin/env python3
"""Bring the Conan CycloneDX SBOM up to BSI TR-03183-2.

    scripts/sbom_enrich.py --sbom build/sbom.cdx.json [--build-type Release]

Called by scripts/sbom.sh right after `conan sbom:cyclonedx`, so every SBOM
this repository produces - locally, in the pipeline, in a release - is the
enriched one.

What the Conan extension emits, and what the German guideline for CRA SBOMs
(TR-03183-2) additionally requires:

    format          CycloneDX 1.4         -> 1.5 (>= 1.5 required)
    SBOM creator    tool only             -> metadata.supplier with URL
    component maker "Conan" placeholder   -> real maker + URL, from
                                             compliance/sbom-suppliers.toml
    component hash  none                  -> SHA-512 of the Conan package

The hash covers the component as it was consumed: the package folder in the
Conan cache, i.e. the exact files the build compiled against. A folder has no
single canonical digest, so the value is the SHA-512 of a manifest - one line
"<sha512 of file>  <relative path>" per file, sorted by path - and the method
is recorded next to it as a property, so anyone can recompute it.

Anything that cannot be filled (a component missing from the supplier map, a
package missing from the cache) is left as it was and reported on stderr. The
compliance report then shows the gap; this script never invents a value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SUPPLIERS = REPO_ROOT / "compliance" / "sbom-suppliers.toml"
SCHEMA_1_5 = "http://cyclonedx.org/schema/bom-1.5.schema.json"
HASH_METHOD = "sha512 of sorted manifest '<sha512>  <path>' over the Conan package folder"


def run_json(command: list[str]) -> object:
    completed = subprocess.run(command, capture_output=True, text=True, check=True, cwd=REPO_ROOT)
    return json.loads(completed.stdout)


def package_folders(build_type: str) -> dict[str, pathlib.Path]:
    """Component name -> package folder in the Conan cache.

    Resolved with the same options scripts/sbom.sh passes to the SBOM
    extension, so the folders belong to the graph the SBOM describes.
    """
    graph = run_json(
        [
            "conan", "graph", "info", str(REPO_ROOT), "--format=json",
            "-s", f"build_type={build_type}", "-o", "&:build_tests=False",
        ]
    )
    nodes = (graph.get("graph") or {}).get("nodes") or {}
    folders: dict[str, pathlib.Path] = {}
    for node in nodes.values():
        name, ref, package_id = node.get("name"), node.get("ref"), node.get("package_id")
        if not name or not ref or not package_id or node.get("recipe") == "Consumer":
            continue
        folder = node.get("package_folder")
        if not folder:
            try:
                folder = subprocess.run(
                    ["conan", "cache", "path", f"{ref}:{package_id}"],
                    capture_output=True, text=True, check=True, cwd=REPO_ROOT,
                ).stdout.strip()
            except subprocess.CalledProcessError:
                folder = None
        if folder and pathlib.Path(folder).is_dir():
            folders[name] = pathlib.Path(folder)
    return folders


def folder_sha512(folder: pathlib.Path) -> str:
    lines = []
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        # conaninfo.txt / conanmanifest.txt describe the package rather than
        # being part of it; they also embed cache-specific data.
        if path.name in ("conaninfo.txt", "conanmanifest.txt"):
            continue
        digest = hashlib.sha512(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(folder).as_posix()}\n")
    return hashlib.sha512("".join(lines).encode("utf-8")).hexdigest()


def entity(entry: dict) -> dict:
    return {"name": entry["name"], "url": [entry["url"]]}


def enrich(sbom: dict, suppliers: dict, folders: dict[str, pathlib.Path]) -> list[str]:
    problems: list[str] = []
    sbom["$schema"] = SCHEMA_1_5
    sbom["specVersion"] = "1.5"

    manufacturer = suppliers.get("manufacturer")
    metadata = sbom.setdefault("metadata", {})
    if manufacturer:
        metadata["supplier"] = entity(manufacturer)
        if isinstance(metadata.get("component"), dict):
            metadata["component"]["supplier"] = entity(manufacturer)

    known = suppliers.get("components", {})
    for component in sbom.get("components") or []:
        name = component.get("name", "")
        if name in known:
            component["supplier"] = entity(known[name])
            component.pop("author", None)  # the "Conan" placeholder
        else:
            problems.append(f"{name}: no entry in compliance/sbom-suppliers.toml")

        folder = folders.get(name)
        if folder is None:
            problems.append(f"{name}: package folder not found in the Conan cache, no hash")
            continue
        component["hashes"] = [{"alg": "SHA-512", "content": folder_sha512(folder)}]
        properties = [p for p in component.get("properties", []) if p.get("name") != "ttg:hash:method"]
        properties.append({"name": "ttg:hash:method", "value": HASH_METHOD})
        component["properties"] = properties
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sbom", type=pathlib.Path, required=True, help="rewritten in place")
    parser.add_argument("--build-type", default="Release")
    args = parser.parse_args(argv)

    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    suppliers = tomllib.loads(SUPPLIERS.read_text(encoding="utf-8"))
    try:
        folders = package_folders(args.build_type)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"sbom-enrich: cannot resolve Conan package folders ({exc}); no hashes added", file=sys.stderr)
        folders = {}

    problems = enrich(sbom, suppliers, folders)
    args.sbom.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")

    hashed = sum(1 for c in sbom.get("components") or [] if c.get("hashes"))
    print(f"sbom-enrich: CycloneDX 1.5, {hashed}/{len(sbom.get('components') or [])} components hashed")
    for problem in problems:
        print(f"sbom-enrich: {problem}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
