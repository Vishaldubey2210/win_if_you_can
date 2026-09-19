from __future__ import annotations
from typing import Any, Dict, Optional
from slopguard.core.models import (
    IdentityResolution,
    IdentityStatus,
    PhantomState,
    PolicyAction,
    PolicyDecision,
    RegistryEvidence,
    RegistryStatus,
    TrustAssessment,
    TrustLevel,
)
from slopguard.memory.phantom import PhantomRecord
from slopguard.policy.config import PolicyConfig, get_profile_config, PolicyProfileName


class DeterministicPolicyEngine:
    """
    Deterministic Policy-as-Code engine for SLOPGUARD.
    Evaluates concrete evidence vectors without probabilistic LLM intuition.
    Configurable via PolicyConfig and PolicyProfile presets (DEVELOPMENT, STRICT_CI, ENTERPRISE).
    """

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        self.config = config or get_profile_config(PolicyProfileName.STRICT_CI)

    def evaluate(
        self,
        identity: IdentityResolution,
        trust: TrustAssessment,
        registry: Optional[RegistryEvidence],
        phantom_record: Optional[PhantomRecord] = None,
    ) -> PolicyDecision:
        reasons = []

        # 1. Standard Library
        if identity.is_stdlib or trust.is_stdlib:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                risk_level="NONE",
                confidence=1.0,
                requires_human_review=False,
                reasons=["Standard library module verified; safe for installation and execution."],
            )

        # 2. Check Temporal Phantom State Change: APPEARED
        if phantom_record and phantom_record.current_state == PhantomState.APPEARED:
            return PolicyDecision(
                action=self.config.phantom_appeared_action,
                risk_level="CRITICAL",
                confidence=0.98,
                requires_human_review=True,
                reasons=[
                    f"CRITICAL STATE CHANGE: Dependency '{identity.resolved_package}' was previously an unresolvable "
                    f"phantom ({phantom_record.first_seen.strftime('%Y-%m-%d')}) and has recently appeared on the registry. "
                    "Potential dependency hallucination pre-registration attack. Quarantine enforced."
                ],
                suggested_fix=f"Conduct manual provenance review for '{identity.resolved_package}' before allowing installation.",
            )

        # 3. Check Definite NOT_FOUND (AI Hallucination / Missing Package)
        if registry and registry.status == RegistryStatus.NOT_FOUND:
            fix = None
            if trust.has_typosquat_risk and trust.typosquat_details:
                fix = f"Did you mean '{trust.typosquat_details.similar_package}'?"
            return PolicyDecision(
                action=self.config.missing_package_action,
                risk_level="HIGH",
                confidence=1.0,
                requires_human_review=False,
                reasons=[
                    f"Package '{identity.resolved_package}' not found on official registry (HTTP 404). "
                    "Installation blocked to prevent dependency confusion and phantom hallucination attacks."
                ],
                suggested_fix=fix,
            )

        # 4. Check Registry Infrastructure Failures (Fail-Safe: HOLD, Never Fail-Open)
        if registry and registry.status in (
            RegistryStatus.RATE_LIMITED,
            RegistryStatus.SERVER_ERROR,
            RegistryStatus.TIMEOUT,
            RegistryStatus.NETWORK_ERROR,
            RegistryStatus.MALFORMED_RESPONSE,
        ):
            action = (
                self.config.registry_429_action
                if registry.status == RegistryStatus.RATE_LIMITED
                else self.config.registry_timeout_action
                if registry.status == RegistryStatus.TIMEOUT
                else self.config.registry_5xx_action
            )
            return PolicyDecision(
                action=action,
                risk_level="MEDIUM",
                confidence=0.90,
                requires_human_review=True,
                reasons=[
                    f"Registry verification failed due to {registry.status.value}: {registry.error_message}. "
                    "Fail-safe posture enforces quarantine until registry status can be authoritatively validated."
                ],
                suggested_fix="Retry scan once registry connectivity is restored.",
            )

        # 5. Check Typosquatting / Unicode Homoglyph Attack
        if trust.has_typosquat_risk and trust.typosquat_details:
            similar = trust.typosquat_details.similar_package
            is_homoglyph = "homoglyph" in trust.typosquat_details.reason.lower()
            if is_homoglyph:
                return PolicyDecision(
                    action=PolicyAction.BLOCK,
                    risk_level="CRITICAL",
                    confidence=1.0,
                    requires_human_review=True,
                    reasons=[
                        f"CRITICAL: Unicode confusable homoglyph attack detected! Package name exhibits "
                        f"deliberate visual spoofing of target '{similar}'."
                    ],
                    suggested_fix=f"Replace spoofed package with authentic '{similar}'.",
                )
            else:
                return PolicyDecision(
                    action=self.config.typosquat_action,
                    risk_level="HIGH",
                    confidence=trust.typosquat_details.confidence,
                    requires_human_review=True,
                    reasons=[
                        f"Potential typosquatting detected: '{identity.resolved_package}' is dangerously close to '{similar}' "
                        f"(edit distance {trust.typosquat_details.distance}, similarity {trust.typosquat_details.similarity_ratio * 100:.1f}%)."
                    ],
                    suggested_fix=f"Replace '{identity.resolved_package}' with verified package '{similar}'.",
                )

        # 6. Check Active Vulnerability Advisories from OSV
        rel_signals = trust.signals.get("release_signals", {})
        highest_adv = rel_signals.get("highest_advisory_severity", "NONE")
        adv_count = rel_signals.get("advisories_count", 0)

        if highest_adv in ("CRITICAL", "HIGH"):
            return PolicyDecision(
                action=self.config.critical_advisory_action,
                risk_level="HIGH",
                confidence=0.98,
                requires_human_review=True,
                reasons=[
                    f"Active security advisory match: {adv_count} advisory(ies) found in OSV database "
                    f"with severity {highest_adv}."
                ],
                suggested_fix="Update package to a non-vulnerable patched version.",
            )
        elif highest_adv == "MEDIUM":
            return PolicyDecision(
                action=self.config.moderate_advisory_action,
                risk_level="MEDIUM",
                confidence=0.90,
                requires_human_review=True,
                reasons=[
                    f"Security advisory match: {adv_count} moderate advisory(ies) found in OSV database."
                ],
                suggested_fix="Review advisory remediation notes.",
            )

        # 7. Check Ambiguous Identity
        if identity.status == IdentityStatus.AMBIGUOUS:
            return PolicyDecision(
                action=self.config.unresolved_identity_action,
                risk_level="MEDIUM",
                confidence=0.50,
                requires_human_review=True,
                reasons=["Package identity is ambiguous or could not be mapped to a known ecosystem."],
            )

        # 8. Check Release Integrity & Age
        if registry and registry.status == RegistryStatus.FOUND:
            if registry.release_count < self.config.min_release_count_required:
                return PolicyDecision(
                    action=self.config.weak_provenance_action,
                    risk_level="MEDIUM",
                    confidence=0.85,
                    requires_human_review=True,
                    reasons=[
                        f"Package contains {registry.release_count} releases; policy requires at least {self.config.min_release_count_required}."
                    ],
                )

            # Check new package with quarantine threshold
            pkg_age = rel_signals.get("package_age_days")
            if pkg_age is not None and pkg_age < self.config.max_package_age_days_for_quarantine:
                if not rel_signals.get("has_repository") or not rel_signals.get("provenance_available"):
                    return PolicyDecision(
                        action=self.config.weak_provenance_action,
                        risk_level="MEDIUM",
                        confidence=0.85,
                        requires_human_review=True,
                        reasons=[
                            f"Newly published package ({pkg_age} days old < {self.config.max_package_age_days_for_quarantine}d threshold) "
                            "with unverified source repository or build provenance."
                        ],
                        suggested_fix="Inspect package publisher and verify source repository.",
                    )

            # Validated & Trusted
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                risk_level="LOW",
                confidence=1.0,
                requires_human_review=False,
                reasons=[
                    f"Package identity verified. Active releases ({registry.release_count}) confirmed on registry. "
                    f"Latest version: {registry.latest_version}."
                ],
            )

        # Default fallback: HOLD for safety
        return PolicyDecision(
            action=PolicyAction.HOLD,
            risk_level="MEDIUM",
            confidence=0.70,
            requires_human_review=True,
            reasons=["Inconclusive evidence; dependency held in quarantine pending review."],
        )

    def simulate(
        self,
        identity: IdentityResolution,
        trust: TrustAssessment,
        registry: Optional[RegistryEvidence],
        phantom_record: Optional[PhantomRecord] = None,
    ) -> Dict[str, Any]:
        """
        Simulate policy gate execution without side effects or package installation.
        Answers: 'What would policy do?'
        """
        decision = self.evaluate(identity, trust, registry, phantom_record)
        return {
            "policy_profile": self.config.profile.value,
            "policy_version": self.config.version,
            "package": identity.resolved_package,
            "simulated_action": decision.action.value,
            "risk_level": decision.risk_level,
            "requires_human_review": decision.requires_human_review,
            "reasons": decision.reasons,
            "suggested_fix": decision.suggested_fix,
        }
