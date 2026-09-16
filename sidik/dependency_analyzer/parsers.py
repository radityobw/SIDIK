"""Parsers for Python dependency manifest files (requirements.txt, pyproject.toml, Pipfile, poetry.lock)."""

import re
import tomllib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class DependencySpec:
    """Represents a declared dependency parsed from a manifest file."""
    package_name: str
    specifier: str
    raw_line: str
    line_number: int
    manifest_type: str


def normalize_package_name(name: str) -> str:
    """Normalizes package name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def parse_requirements_txt(content: str) -> List[DependencySpec]:
    """Parses standard requirements.txt content."""
    specs = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Skip empty lines, comments, and pip options (-r, -i, etc.)
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue

        # Strip inline comments
        if " #" in stripped:
            stripped = stripped.split(" #", 1)[0].strip()

        # Match package name and specifier: e.g., requests==2.25.1, django>=3.0,<3.2
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*)?$", stripped)
        if match:
            pkg_name = normalize_package_name(match.group(1))
            spec = match.group(2).strip() if match.group(2) else "*"
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
                raw_line=line,
                line_number=idx,
                manifest_type="requirements.txt"
            ))

    return specs


def parse_pyproject_toml(content: str) -> List[DependencySpec]:
    """Parses pyproject.toml adhering to PEP 621 or Poetry schemas."""
    specs = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    # 1. PEP 621 project.dependencies
    pep621_deps = data.get("project", {}).get("dependencies", [])
    if isinstance(pep621_deps, list):
        for dep in pep621_deps:
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*)?$", dep.strip())
            if match:
                pkg_name = normalize_package_name(match.group(1))
                spec = match.group(2).strip() if match.group(2) else "*"
                specs.append(DependencySpec(
                    package_name=pkg_name,
                    specifier=spec,
                    raw_line=dep,
                    line_number=0,
                    manifest_type="pyproject.toml"
                ))

    # 2. Poetry tool.poetry.dependencies
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for pkg, val in poetry_deps.items():
            if pkg.lower() == "python":
                continue
            pkg_name = normalize_package_name(pkg)
            if isinstance(val, str):
                spec = val
            elif isinstance(val, dict) and "version" in val:
                spec = str(val["version"])
            else:
                spec = "*"
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
                raw_line=f"{pkg} = {val}",
                line_number=0,
                manifest_type="pyproject.toml"
            ))

    return specs


def parse_pipfile(content: str) -> List[DependencySpec]:
    """Parses Pipfile TOML sections."""
    specs = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for pkg, spec in packages.items():
            specs.append(DependencySpec(
                package_name=normalize_package_name(pkg),
                specifier=str(spec).strip('"\''),
                raw_line=f"{pkg} = {spec}",
                line_number=0,
                manifest_type="Pipfile"
            ))

    return specs


def parse_poetry_lock(content: str) -> List[DependencySpec]:
    """Parses poetry.lock TOML package declarations."""
    specs = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return specs

    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            specs.append(DependencySpec(
                package_name=normalize_package_name(name),
                specifier=f"=={version}",
                raw_line=f"name = {name}, version = {version}",
                line_number=0,
                manifest_type="poetry.lock"
            ))

    return specs


def parse_setup_py(content: str) -> List[DependencySpec]:
    """Parses install_requires declarations in setup.py."""
    specs = []
    # Match install_requires=[...] block
    match_block = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if not match_block:
        return specs

    raw_items = match_block.group(1)
    dep_strings = re.findall(r"['\"]([^'\"]+)['\"]", raw_items)

    for idx, dep in enumerate(dep_strings, start=1):
        dep_clean = dep.strip()
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*)?$", dep_clean)
        if match:
            pkg_name = normalize_package_name(match.group(1))
            spec = match.group(2).strip() if match.group(2) else "*"
            specs.append(DependencySpec(
                package_name=pkg_name,
                specifier=spec,
                raw_line=dep_clean,
                line_number=idx,
                manifest_type="setup.py"
            ))

    return specs

