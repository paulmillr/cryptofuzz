#!/usr/bin/env python3

import json
import os
import re
from pathlib import Path


REQUIRED_ADAPTER_FILES = ("package.json", "package-lock.json", "Makefile", "build.mjs")
PROJECT_NAME_PATTERN = re.compile(r"^noble-[a-z0-9]+(?:-[a-z0-9]+)*$")


def required_environment_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return Path(value)


def required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def read_package(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as package_file:
            package = json.load(package_file)
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Cannot read package manifest {path}: {error}") from error

    if not isinstance(package, dict):
        raise SystemExit(f"Package manifest must contain an object: {path}")
    return package


def main() -> None:
    adapters_root = required_environment_path("ADAPTERS_ROOT")
    source_root = required_environment_path("NOBLE_SOURCE_ROOT")
    project_name = required_environment_value("PROJECT_NAME")
    github_output = required_environment_path("GITHUB_OUTPUT")

    if not PROJECT_NAME_PATTERN.fullmatch(project_name):
        raise SystemExit(f"Unsupported caller repository name: {project_name}")

    module_directory = adapters_root / project_name
    missing_files = [
        filename for filename in REQUIRED_ADAPTER_FILES
        if not (module_directory / filename).is_file()
    ]
    if missing_files:
        raise SystemExit(f"No complete Cryptofuzz Noble adapter exists for {project_name}")

    expected_package = f"@noble/{project_name.removeprefix('noble-')}"
    expected_adapter = f"cryptofuzz-{project_name}"
    adapter = read_package(module_directory / "package.json")
    source = read_package(source_root / "package.json")

    if adapter.get("name") != expected_adapter:
        raise SystemExit(f"Adapter package name must be {expected_adapter}")

    dependencies = adapter.get("dependencies")
    if not isinstance(dependencies, dict) or expected_package not in dependencies:
        raise SystemExit(f"{expected_adapter} does not depend on {expected_package}")

    if source.get("name") != expected_package:
        raise SystemExit(f"Caller package name must be {expected_package}")

    max_len = 65536 if project_name == "noble-post-quantum" else 4096
    try:
        with github_output.open("a", encoding="utf-8") as output_file:
            output_file.write(f"module={project_name}\n")
            output_file.write(f"source_package={expected_package}\n")
            output_file.write(f"max_len={max_len}\n")
    except OSError as error:
        raise SystemExit(f"Cannot write GitHub Actions output {github_output}: {error}") from error

    print(f"Selected {project_name} for {expected_package}")


if __name__ == "__main__":
    main()
