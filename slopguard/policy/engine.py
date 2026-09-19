from __future__ import annotations
from typing import Optional
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


class DeterministicPolicyEngine:
    """
    Deterministic Policy-as-Code engine for SLOPGUARD.
    Evaluates concrete evidence vectors without probabilistic LLM intuition.
    Produces ALLOW, HOLD, BLOCK, or ALERT decisions with explicit rationale.
    """

    def evaluate(
        self,
        identity: IdentityResolution,
        trust: TrustAssessment,
        registry: Optional[RegistryEvidence],
        phantom_record: Optional[PhantomRecord] = None,
    ) -> PolicyDecision:
        reasons = []

        # 1. Check Standard Library
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
                action=PolicyAction.ALERT,
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
                action=PolicyAction.BLOCK,
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
            return PolicyDecision(
                action=PolicyAction.HOLD,
                risk_level="MEDIUM",
                confidence=0.90,
                requires_human_review=True,
                reasons=[
                    f"Registry verification failed due to {registry.status.value}: {registry.error_message}. "
                    "Fail-safe posture enforces HOLD until registry status can be authoritatively validated."
                ],
                suggested_fix="Retry scan once registry connectivity is restored.",
            )

        # 5. Check Typosquatting Risk
        if trust.has_typosquat_risk and trust.typosquat_details:
            similar = trust.typosquat_details.similar_package
            return PolicyDecision(
                action=PolicyAction.HOLD,
                risk_level="HIGH",
                confidence=trust.typosquat_details.confidence,
                requires_human_review=True,
                reasons=[
                    f"Potential typosquatting detected: '{identity.resolved_package}' is dangerously close to '{similar}' "
                    f"(edit distance {trust.typosquat_details.distance}, similarity {trust.typosquat_details.similarity_ratio * 100:.1f}%)."
                ],
                suggested_fix=f"Replace '{identity.resolved_package}' with verified package '{similar}'.",
            )

        # 6. Check Ambiguous Identity
        if identity.status == IdentityStatus.AMBIGUOUS:
            return PolicyDecision(
                action=PolicyAction.HOLD,
                risk_level="MEDIUM",
                confidence=0.50,
                requires_human_review=True,
                reasons=["Package identity is ambiguous or could not be mapped to a known ecosystem."],
            )

        # 7. Check Verified Package with Active Releases
        if registry and registry.status == RegistryStatus.FOUND:
            if registry.release_count == 0:
                return PolicyDecision(
                    action=PolicyAction.HOLD,
                    risk_level="MEDIUM",
                    confidence=0.85,
                    requires_human_review=True,
                    reasons=["Package exists on registry but contains 0 published releases."],
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
