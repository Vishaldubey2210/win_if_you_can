from __future__ import annotations
from typing import List, Optional
from slopguard.core.models import (
    Ecosystem,
    IdentityResolution,
    IdentityStatus,
    RegistryEvidence,
    RegistryStatus,
    TrustAssessment,
    TrustLevel,
)
from slopguard.evidence.models import ProvenanceSignal, SecurityAdvisory
from slopguard.trust.signals import ReleaseSignalAnalyzer
from slopguard.trust.typosquat import TyposquatDetector


class TrustEvaluator:
    """
    Evaluates multi-dimensional, release-aware trust signals without black-box AI scoring.
    Combines canonical identity status, registry verification, release metrics,
    OSV vulnerability advisories, provenance availability, and typosquatting detection.
    """

    def __init__(self) -> None:
        self.typosquat_detector = TyposquatDetector()

    def evaluate(
        self,
        identity: IdentityResolution,
        registry: Optional[RegistryEvidence],
        advisories: Optional[List[SecurityAdvisory]] = None,
        provenance: Optional[ProvenanceSignal] = None,
    ) -> TrustAssessment:
        package_name = identity.resolved_package
        ecosystem = identity.ecosystem
        reasons: List[str] = []
        signals = {}

        # 1. Standard Library
        if identity.is_stdlib or identity.status == IdentityStatus.STDLIB:
            return TrustAssessment(
                package_name=package_name,
                ecosystem=ecosystem,
                level=TrustLevel.VERIFIED,
                identity_verified=True,
                registry_verified=True,
                is_stdlib=True,
                has_typosquat_risk=False,
                signals={
                    "type": "standard_library",
                    "identity": "VERIFIED",
                    "registry": "STDLIB",
                    "release": "SYSTEM",
                    "repository": "OFFICIAL",
                    "provenance": "BUILTIN",
                    "advisory": "NONE",
                },
                reasons=["Package is part of the standard library runtime distribution"],
            )

        # 2. Typosquat Check
        typosquat = self.typosquat_detector.check(package_name, ecosystem)
        has_typosquat = typosquat is not None
        if has_typosquat:
            reasons.append(f"Potential typosquat: {typosquat.reason}")
            signals["typosquat"] = typosquat.model_dump()

        # 3. Release & Temporal Signals Analysis
        rel_signals = ReleaseSignalAnalyzer.analyze(registry, advisories, provenance)
        signals["release_signals"] = rel_signals.model_dump()

        # Build explicit dimensions
        signals["identity"] = "VERIFIED" if identity.status in (IdentityStatus.RESOLVED, IdentityStatus.ALIASED) else "UNVERIFIED"
        signals["registry"] = registry.status.value if registry else "UNCHECKED"
        signals["repository"] = "LINKED" if rel_signals.has_repository else "UNLINKED"
        signals["provenance"] = "AVAILABLE" if rel_signals.provenance_available else "UNAVAILABLE"
        signals["advisory"] = f"{rel_signals.highest_advisory_severity}_MATCH" if rel_signals.advisories_count > 0 else "NONE"

        # 4. Registry Status Checks
        registry_verified = False
        identity_verified = identity.status in (IdentityStatus.RESOLVED, IdentityStatus.ALIASED)

        if not registry:
            level = TrustLevel.UNRESOLVED
            reasons.append("No registry verification was performed")
        elif registry.status == RegistryStatus.FOUND:
            registry_verified = True
            signals["release_count"] = registry.release_count
            signals["latest_version"] = registry.latest_version
            if registry.repository_url:
                signals["repository_url"] = registry.repository_url

            if has_typosquat:
                level = TrustLevel.SUSPICIOUS
                reasons.append(
                    f"Package exists on registry, but exhibits suspicious similarity to target '{typosquat.similar_package}'"
                )
            elif rel_signals.highest_advisory_severity in ("CRITICAL", "HIGH"):
                level = TrustLevel.SUSPICIOUS
                reasons.append(
                    f"Active security advisory match: {rel_signals.advisories_count} advisory(ies) found with severity {rel_signals.highest_advisory_severity}"
                )
            elif registry.release_count == 0:
                level = TrustLevel.REVIEW
                reasons.append("Package exists on registry, but contains 0 releases or downloadable artifacts")
            elif rel_signals.is_new_package and registry.release_count <= 2:
                level = TrustLevel.REVIEW
                reasons.append(
                    f"Newly published package ({rel_signals.package_age_days} days old) with limited release history ({registry.release_count} release(s))"
                )
            else:
                level = TrustLevel.VERIFIED
                reasons.append(
                    f"Verified on registry with {registry.release_count} releases. Latest: {registry.latest_version}"
                )
        elif registry.status == RegistryStatus.NOT_FOUND:
            level = TrustLevel.UNRESOLVED
            reasons.append("Package does not exist on official registry (HTTP 404)")
        elif registry.status in (
            RegistryStatus.RATE_LIMITED,
            RegistryStatus.SERVER_ERROR,
            RegistryStatus.TIMEOUT,
            RegistryStatus.NETWORK_ERROR,
        ):
            level = TrustLevel.REVIEW
            reasons.append(
                f"Registry verification inconclusive due to network or server condition: {registry.status.value}"
            )
        else:
            level = TrustLevel.REVIEW
            reasons.append(f"Registry returned non-standard status: {registry.status.value}")

        # Add flags from release signal analyzer
        for flag in rel_signals.flags:
            if flag not in reasons:
                reasons.append(flag)

        return TrustAssessment(
            package_name=package_name,
            ecosystem=ecosystem,
            level=level,
            identity_verified=identity_verified,
            registry_verified=registry_verified,
            is_stdlib=False,
            has_typosquat_risk=has_typosquat,
            typosquat_details=typosquat,
            signals=signals,
            reasons=reasons,
        )
