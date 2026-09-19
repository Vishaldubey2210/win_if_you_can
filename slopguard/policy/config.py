from __future__ import annotations
from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel, Field
from slopguard.core.models import PolicyAction


class PolicyProfileName(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    STRICT_CI = "STRICT_CI"
    ENTERPRISE = "ENTERPRISE"


PolicyProfile = PolicyProfileName


class PolicyConfig(BaseModel):
    name: str = "default"
    profile: PolicyProfileName = PolicyProfileName.STRICT_CI
    version: str = "1.0.0"
    description: str = "Deterministic supply-chain firewall policy rules."

    # Rules mapping conditions to actions
    missing_package_action: PolicyAction = PolicyAction.BLOCK
    unresolved_identity_action: PolicyAction = PolicyAction.BLOCK
    registry_timeout_action: PolicyAction = PolicyAction.HOLD
    registry_429_action: PolicyAction = PolicyAction.HOLD
    registry_5xx_action: PolicyAction = PolicyAction.HOLD
    critical_advisory_action: PolicyAction = PolicyAction.BLOCK
    moderate_advisory_action: PolicyAction = PolicyAction.HOLD
    phantom_appeared_action: PolicyAction = PolicyAction.ALERT
    typosquat_action: PolicyAction = PolicyAction.BLOCK
    weak_provenance_action: PolicyAction = PolicyAction.HOLD
    max_package_age_days_for_quarantine: int = 14
    min_release_count_required: int = 1

    @classmethod
    def from_profile(cls, profile: PolicyProfileName | str) -> PolicyConfig:
        if isinstance(profile, str):
            profile = PolicyProfileName(profile.upper())
        return get_profile_config(profile)

    @property
    def rules(self) -> Dict[str, PolicyAction]:
        return {
            "missing_package": self.missing_package_action,
            "unresolved_identity": self.unresolved_identity_action,
            "registry_timeout": self.registry_timeout_action,
            "registry_429": self.registry_429_action,
            "registry_5xx": self.registry_5xx_action,
            "critical_advisory": self.critical_advisory_action,
            "moderate_advisory": self.moderate_advisory_action,
            "phantom_appeared": self.phantom_appeared_action,
            "typosquat": self.typosquat_action,
            "weak_provenance": self.weak_provenance_action,
        }


def get_profile_config(profile: PolicyProfileName) -> PolicyConfig:
    """Returns pre-configured Policy-as-Code profile."""
    if profile == PolicyProfileName.DEVELOPMENT:
        return PolicyConfig(
            name="development_profile",
            profile=PolicyProfileName.DEVELOPMENT,
            weak_provenance_action=PolicyAction.ALLOW,
            moderate_advisory_action=PolicyAction.ALLOW,
            max_package_age_days_for_quarantine=3,
        )
    elif profile == PolicyProfileName.ENTERPRISE:
        return PolicyConfig(
            name="enterprise_profile",
            profile=PolicyProfileName.ENTERPRISE,
            weak_provenance_action=PolicyAction.HOLD,
            max_package_age_days_for_quarantine=30,
            min_release_count_required=3,
        )
    else:  # STRICT_CI default
        return PolicyConfig(
            name="strict_ci_profile",
            profile=PolicyProfileName.STRICT_CI,
        )
