#!/usr/bin/env python3
import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: str) -> dict:
    with (ROOT / path).open(encoding="utf-8") as file:
        return json.load(file)


def load_toml(path: str, version_section: str) -> dict:
    if tomllib is None:
        return {"version": read_toml_version(path, version_section)}

    with (ROOT / path).open("rb") as file:
        return tomllib.load(file)


def read_toml_version(path: str, section: str) -> str:
    section_header = f"[{section}]"
    in_section = False
    version_pattern = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')

    with (ROOT / path).open(encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_section = stripped == section_header
                continue
            if not in_section:
                continue
            match = version_pattern.match(stripped)
            if match:
                return match.group(1)

    raise KeyError(f"missing version in {path} section {section_header}")


def main() -> int:
    cargo = load_toml("Cargo.toml", "package")
    pyproject = load_toml("pyproject.toml", "project")
    package = load_json("package.json")
    targets = load_json("npm/prebuilt-targets.json")

    versions = {
        "Cargo.toml package.version": cargo.get("version")
        or cargo["package"]["version"],
        "pyproject.toml project.version": pyproject.get("version")
        or pyproject["project"]["version"],
        "package.json version": package["version"],
    }
    expected = versions["Cargo.toml package.version"]

    optional_dependencies = package.get("optionalDependencies", {})
    for target_key, target in sorted(targets.items()):
        package_name = target["packageName"]
        versions[f"package.json optionalDependencies.{package_name}"] = (
            optional_dependencies.get(package_name)
        )
        if package_name not in optional_dependencies:
            print(
                f"missing optional dependency for {target_key}: {package_name}",
                file=sys.stderr,
            )
            return 1

    mismatches = [
        f"{name}={value!r}"
        for name, value in versions.items()
        if value != expected
    ]
    if mismatches:
        print(f"release version mismatch; expected {expected!r}", file=sys.stderr)
        for mismatch in mismatches:
            print(f"  {mismatch}", file=sys.stderr)
        return 1

    tag_name = os.environ.get("RELEASE_TAG")
    github_ref_type = os.environ.get("GITHUB_REF_TYPE")
    github_ref_name = os.environ.get("GITHUB_REF_NAME")
    if tag_name is None and github_ref_type == "tag":
        tag_name = github_ref_name

    require_release_tag = os.environ.get("REQUIRE_RELEASE_TAG", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if tag_name:
        if not tag_name.startswith("v"):
            print(f"release tag must start with 'v': {tag_name}", file=sys.stderr)
            return 1
        tag_version = tag_name[1:]
        if tag_version != expected:
            print(
                f"release tag {tag_name!r} does not match package version {expected!r}",
                file=sys.stderr,
            )
            return 1
    elif require_release_tag:
        print("publishing requires a v* release tag", file=sys.stderr)
        return 1

    print(f"release version ok: {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
