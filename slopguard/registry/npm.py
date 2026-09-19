from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
import urllib.parse
from slopguard.core.models import Ecosystem, RegistryEvidence, RegistryStatus
from slopguard.registry.base import BaseRegistryAdapter


class NPMAdapter(BaseRegistryAdapter):
    """
    Adapter for official npm registry (https://registry.npmjs.org/<package>).
    Correctly handles URL escaping for scoped packages (@scope/pkg -> @scope%2Fpkg).
    """

    def __init__(self, timeout_seconds: float = 8.0, max_retries: int = 2) -> None:
        super().__init__(
            ecosystem=Ecosystem.NPM,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    def get_package_url(self, package_name: str) -> str:
        clean = package_name.strip()
        if clean.startswith("@"):
            parts = clean.split("/", 1)
            if len(parts) == 2:
                escaped_scope = urllib.parse.quote(parts[0], safe="")
                escaped_pkg = urllib.parse.quote(parts[1], safe="")
                return f"https://registry.npmjs.org/{escaped_scope}%2F{escaped_pkg}"
        return f"https://registry.npmjs.org/{urllib.parse.quote(clean, safe='')}"

    def parse_metadata_response(
        self, package_name: str, status_code: int, data: dict, latency_ms: float
    ) -> RegistryEvidence:
        dist_tags = data.get("dist-tags", {})
        latest_version = dist_tags.get("latest")
        versions_dict = data.get("versions", {})
        all_versions = list(versions_dict.keys())
        release_count = len(all_versions)

        # Timestamps
        time_dict = data.get("time", {})
        first_release_time: Optional[datetime] = None
        latest_release_time: Optional[datetime] = None

        if time_dict:
            created_str = time_dict.get("created")
            if created_str:
                try:
                    first_release_time = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                except Exception:
                    pass
            modified_str = time_dict.get("modified")
            if modified_str:
                try:
                    latest_release_time = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                except Exception:
                    pass

        # Repository URL
        repo_data = data.get("repository")
        repo_url = None
        if isinstance(repo_data, dict):
            repo_url = repo_data.get("url")
        elif isinstance(repo_data, str):
            repo_url = repo_data

        if repo_url and repo_url.startswith("git+"):
            repo_url = repo_url[4:]
        if repo_url and repo_url.endswith(".git"):
            repo_url = repo_url[:-4]

        # Author / Maintainers
        author_data = data.get("author")
        author_name = None
        if isinstance(author_data, dict):
            author_name = author_data.get("name")
        elif isinstance(author_data, str):
            author_name = author_data

        maintainers_data = data.get("maintainers", [])
        maintainer_names = []
        if isinstance(maintainers_data, list):
            for m in maintainers_data:
                if isinstance(m, dict) and "name" in m:
                    maintainer_names.append(m["name"])
                elif isinstance(m, str):
                    maintainer_names.append(m)

        home_url = data.get("homepage")
        description = data.get("description")

        return RegistryEvidence(
            package_name=package_name,
            ecosystem=Ecosystem.NPM,
            status=RegistryStatus.FOUND,
            http_status=status_code,
            latest_version=latest_version,
            all_versions=all_versions[-20:],
            release_count=release_count,
            first_release_time=first_release_time,
            latest_release_time=latest_release_time,
            repository_url=repo_url,
            homepage_url=home_url,
            author=author_name,
            maintainers=maintainer_names,
            description_summary=description,
            latency_ms=latency_ms,
        )
