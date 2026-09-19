import pytest
from slopguard.core.models import (
    Ecosystem,
    IdentityResolution,
    IdentityStatus,
    PolicyAction,
    RegistryEvidence,
    RegistryStatus,
    TrustAssessment,
    TrustLevel,
)
from slopguard.policy.config import PolicyProfileName, get_profile_config
from slopguard.policy.engine import DeterministicPolicyEngine

def test_policy_profiles():
    # 1. Strict CI profile
    strict_engine = DeterministicPolicyEngine(config=get_profile_config(PolicyProfileName.STRICT_CI))
    ident = IdentityResolution(
        input_name="missing-lib",
        normalized_name="missing-lib",
        resolved_package="missing-lib",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg_missing = RegistryEvidence(
        package_name="missing-lib",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.NOT_FOUND,
    )
    trust = TrustAssessment(
        package_name="missing-lib",
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.UNRESOLVED,
        identity_verified=True,
        registry_verified=False,
    )
    decision = strict_engine.evaluate(ident, trust, reg_missing)
    assert decision.action == PolicyAction.BLOCK

    # 2. Simulation test
    sim = strict_engine.simulate(ident, trust, reg_missing)
    assert sim["simulated_action"] == "BLOCK"
    assert sim["policy_profile"] == "STRICT_CI"
    assert "missing-lib" in sim["package"]
