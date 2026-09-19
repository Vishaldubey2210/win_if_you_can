from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from slopguard.core.models import RegistryEvidence
from slopguard.evidence.models import ProvenanceSignal, SecurityAdvisory


class ReleaseTrustSignals(BaseModel):
    package_name: str
    package_age_days: Optional[int] = None
    latest_release_age_days: Optional[int] = None
    total_releases: int = 0
    is_new_package: bool = False  # < 14 days old
    is_brand_new_release: bool = False  # < 48 hours old
    has_repository: bool = False
    repository_url: Optional[str] = None
    provenance_available: bool = False
    advisories_count: int = 0
    highest_advisory_severity: str = "NONE"
    flags: List[str] = Field(default_factory=list)


class ReleaseSignalAnalyzer:
    """
    Computes objective, measurable temporal and release signals from evidence.
    Never fabricates safety claims.
    """

    @staticmethod
    def analyze(
        registry: Optional[RegistryEvidence],
        advisories: Optional[List[SecurityAdvisory]] = None,
        provenance: Optional[ProvenanceSignal] = None,
    ) -> ReleaseTrustSignals:
        if not registry:
            return ReleaseTrustSignals(package_name="unknown")

        now = datetime.now(timezone.utc)
        age_days = None
        latest_age_days = None
        flags: List[str] = []

        # Calculate package age from first release
        if registry.first_release_time:
            first_dt = registry.first_release_time
            if first_dt.tzinfo is None:
                first_dt = first_dt.replace(tzinfo=timezone.utc)
            age_days = max(0, (now - first_dt).days)

        # Calculate latest release age
        if registry.latest_release_time:
            latest_dt = registry.latest_release_time
            if latest_dt.tzinfo is None:
                latest_dt = latest_dt.replace(tzinfo=timezone.utc)
            latest_age_days = max(0, (now - latest_dt).days)

        is_new_pkg = age_days is not None and age_days < 14
        if is_new_pkg:
            flags.append(f"Package first released {age_days} days ago (new package)")

        is_brand_new_rel = latest_age_days is not None and latest_age_days < 2
        if is_brand_new_rel:
            flags.append("Latest release uploaded within the last 48 hours")

        if registry.release_count == 1 and is_new_pkg:
            flags.append("Single release on a newly registered package")

        has_repo = bool(registry.repository_url)
        if not has_repo:
            flags.append("No source repository linkage in registry metadata")

        # Advisories
        adv_count = len(advisories) if advisories else 0
        highest_sev = "NONE"
        if advisories:
            severities = [a.severity.upper() for a in advisories]
            if "CRITICAL" in severities:
                highest_sev = "CRITICAL"
            elif "HIGH" in severities:
                highest_sev = "HIGH"
            elif "MEDIUM" in severities:
                highest_sev = "MEDIUM"
            elif "LOW" in severities:
                highest_sev = "LOW"
            flags.append(f"{adv_count} active security advisory match(es); highest severity: {highest_sev}")

        # Provenance
        has_prov = provenance.has_provenance if provenance else False
        if has_prov:
            flags.append("Build provenance or package attestation verified")

        return ReleaseTrustSignals(
            package_name=registry.package_name,
            package_age_days=age_days,
            latest_release_age_days=latest_age_days,
            total_releases=registry.release_count,
            is_new_package=is_new_pkg,
            is_brand_new_release=is_brand_new_rel,
            has_repository=has_repo,
            repository_url=registry.repository_url,
            provenance_available=has_prov,
            advisories_count=adv_count,
            highest_advisory_severity=highest_sev,
            flags=flags,
        )
