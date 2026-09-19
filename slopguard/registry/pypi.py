from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
from slopguard.core.models import Ecosystem, RegistryEvidence, RegistryStatus
from slopguard.registry.base import BaseRegistryAdapter


class PyPIAdapter(BaseRegistryAdapter):
    """
    Adapter for PyPI official JSON API (https://pypi.org/pypi/<package>/json).
    """

    def __init__(self, timeout_seconds: float = 8.0, max_retries: int = 2) -> None:
        super().__init__(
            ecosystem=Ecosystem.PYPI,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    def get_package_url(self, package_name: str) -> str:
        # PyPI expects normalized or exact package name in URL
        return f"https://pypi.org/pypi/{package_name}/json"

    def parse_metadata_response(
        self, package_name: str, status_code: int, data: dict, latency_ms: float
    ) -> RegistryEvidence:
        info = data.get("info", {})
        releases = data.get("releases", {})

        latest_version = info.get("version")
        all_versions = list(releases.keys())
        release_count = len(all_versions)

        # Extract timestamps
        first_release_time: Optional[datetime] = None
        latest_release_time: Optional[datetime] = None

        all_upload_times: List[datetime] = []
        for v, file_list in releases.items():
            if isinstance(file_list, list):
                for f in file_list:
                    if isinstance(f, dict):
                        ts_str = f.get("upload_time_iso_8601") or f.get("upload_time")
                        if ts_str:
                            try:
                                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                                all_upload_times.append(dt)
                            except Exception:
                                pass

        if all_upload_times:
            all_upload_times.sort()
            first_release_time = all_upload_times[0]
            latest_release_time = all_upload_times[-1]

        # Extract URLs
        project_urls = info.get("project_urls") or {}
        repo_url = (
            project_urls.get("Repository")
            or project_urls.get("Source")
            or project_urls.get("Source Code")
            or project_urls.get("Code")
            or project_urls.get("GitHub")
            or info.get("home_page")
        )
        home_url = info.get("home_page") or project_urls.get("Homepage")

        author = info.get("author") or info.get("maintainer")
        summary = info.get("summary")

        return RegistryEvidence(
            package_name=package_name,
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.FOUND,
            http_status=status_code,
            latest_version=latest_version,
            all_versions=all_versions[-20:],  # keep recent 20
            release_count=release_count,
            first_release_time=first_release_time,
            latest_release_time=latest_release_time,
            repository_url=repo_url,
            homepage_url=home_url,
            author=author,
            maintainers=[author] if author else [],
            description_summary=summary,
            latency_ms=latency_ms,
        )
