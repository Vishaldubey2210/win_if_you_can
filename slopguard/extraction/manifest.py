from __future__ import annotations
import json
import re
import tomllib
from typing import List, Optional
from slopguard.core.models import DependencySourceType, Ecosystem, ExtractedDependency


class ManifestExtractor:
    """
    Parses manifest files (requirements.txt, pyproject.toml, package.json, package-lock.json)
    into structured ExtractedDependency instances.
    """

    @staticmethod
    def parse_requirements_txt(content: str, file_path: str = "requirements.txt") -> List[ExtractedDependency]:
        results: List[ExtractedDependency] = []
        lines = content.splitlines()

        # Regex for PEP 508 package specification: package_name [extras] specifier ; markers
        spec_pattern = re.compile(
            r"""^([a-zA-Z0-9_\-\.]+)\s*(\[[^\]]*\])?\s*([=<>!~@].*)?$"""
        )

        for line_idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            # Skip empty lines and full comments
            if not line or line.startswith("#"):
                continue

            # Strip inline comments if not inside quotes or markers
            if "#" in line:
                line = line.split("#", 1)[0].strip()

            # Skip flags like -r, -i, -f, --extra-index-url
            if line.startswith(("-", "--")):
                continue

            # Strip environment markers e.g. ; python_version < "3.11"
            if ";" in line:
                line = line.split(";", 1)[0].strip()

            match = spec_pattern.match(line)
            if match:
                pkg_name = match.group(1)
                version_spec = match.group(3).strip() if match.group(3) else None
                results.append(
                    ExtractedDependency(
                        name=pkg_name,
                        version_constraint=version_spec,
                        ecosystem=Ecosystem.PYPI,
                        source_type=DependencySourceType.MANIFEST,
                        file_path=file_path,
                        line_number=line_idx,
                        raw_statement=raw_line.strip(),
                        is_stdlib=False,
                        is_relative=False,
                    )
                )

        return results

    @staticmethod
    def parse_pyproject_toml(content: str, file_path: str = "pyproject.toml") -> List[ExtractedDependency]:
        results: List[ExtractedDependency] = []
        try:
            data = tomllib.loads(content)
        except Exception as exc:
            raise ValueError(f"Failed to parse TOML in {file_path}: {exc}") from exc

        # 1. PEP 621 dependencies: [project.dependencies]
        project = data.get("project", {})
        deps = project.get("dependencies", [])
        if isinstance(deps, list):
            req_content = "\n".join(deps)
            results.extend(ManifestExtractor.parse_requirements_txt(req_content, file_path=file_path))

        # Optional dependencies
        optional_deps = project.get("optional-dependencies", {})
        if isinstance(optional_deps, dict):
            for group_name, group_list in optional_deps.items():
                if isinstance(group_list, list):
                    req_content = "\n".join(group_list)
                    results.extend(ManifestExtractor.parse_requirements_txt(req_content, file_path=file_path))

        # 2. Poetry dependencies: [tool.poetry.dependencies]
        tool_poetry = data.get("tool", {}).get("poetry", {})
        poetry_deps = tool_poetry.get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for name, spec in poetry_deps.items():
                if name.lower() == "python":
                    continue
                version_str = spec if isinstance(spec, str) else spec.get("version") if isinstance(spec, dict) else None
                results.append(
                    ExtractedDependency(
                        name=name,
                        version_constraint=str(version_str) if version_str else None,
                        ecosystem=Ecosystem.PYPI,
                        source_type=DependencySourceType.MANIFEST,
                        file_path=file_path,
                        is_stdlib=False,
                        is_relative=False,
                    )
                )

        return results

    @staticmethod
    def parse_package_json(content: str, file_path: str = "package.json") -> List[ExtractedDependency]:
        results: List[ExtractedDependency] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Failed to parse JSON in {file_path}: {exc}") from exc

        dependency_fields = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
        for field in dependency_fields:
            deps_dict = data.get(field, {})
            if isinstance(deps_dict, dict):
                for pkg_name, version_spec in deps_dict.items():
                    results.append(
                        ExtractedDependency(
                            name=pkg_name,
                            version_constraint=str(version_spec),
                            ecosystem=Ecosystem.NPM,
                            source_type=DependencySourceType.MANIFEST,
                            file_path=file_path,
                            is_stdlib=False,
                            is_relative=False,
                        )
                    )

        return results
