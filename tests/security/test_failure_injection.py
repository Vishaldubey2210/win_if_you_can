import pytest
from slopguard.core.models import (
    Ecosystem,
    IdentityResolution,
    IdentityStatus,
    PhantomState,
    PolicyAction,
    RegistryEvidence,
    RegistryStatus,
    TrustAssessment,
    TrustLevel,
)
from slopguard.policy.engine import DeterministicPolicyEngine
from slopguard.memory.phantom import PhantomRecord

@pytest.fixture
def policy_engine():
    return DeterministicPolicyEngine()

def test_rate_limit_enforces_hold(policy_engine):
    ident = IdentityResolution(
        input_name="critical-pkg",
        normalized_name="critical-pkg",
        resolved_package="critical-pkg",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name="critical-pkg",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.RATE_LIMITED,
        http_status=429,
        error_message="HTTP 429 Too Many Requests",
    )
    trust = TrustAssessment(
        package_name="critical-pkg",
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.REVIEW,
        identity_verified=True,
        registry_verified=False,
    )

    decision = policy_engine.evaluate(ident, trust, reg)
    assert decision.action == PolicyAction.HOLD
    assert decision.requires_human_review is True
    assert "429" in decision.reasons[0]

def test_server_error_500_enforces_hold(policy_engine):
    ident = IdentityResolution(
        input_name="critical-pkg",
        normalized_name="critical-pkg",
        resolved_package="critical-pkg",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name="critical-pkg",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.SERVER_ERROR,
        http_status=500,
        error_message="HTTP 500 Internal Server Error",
    )
    trust = TrustAssessment(
        package_name="critical-pkg",
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.REVIEW,
        identity_verified=True,
        registry_verified=False,
    )

    decision = policy_engine.evaluate(ident, trust, reg)
    assert decision.action == PolicyAction.HOLD
    assert decision.requires_human_review is True

def test_timeout_enforces_hold(policy_engine):
    ident = IdentityResolution(
        input_name="timeout-pkg",
        normalized_name="timeout-pkg",
        resolved_package="timeout-pkg",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name="timeout-pkg",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.TIMEOUT,
        error_message="Timed out after 8s",
    )
    trust = TrustAssessment(
        package_name="timeout-pkg",
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.REVIEW,
        identity_verified=True,
        registry_verified=False,
    )

    decision = policy_engine.evaluate(ident, trust, reg)
    assert decision.action == PolicyAction.HOLD
    assert decision.requires_human_review is True

def test_not_found_enforces_block(policy_engine):
    ident = IdentityResolution(
        input_name="hallucinated-package-xyz",
        normalized_name="hallucinated-package-xyz",
        resolved_package="hallucinated-package-xyz",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name="hallucinated-package-xyz",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.NOT_FOUND,
        http_status=404,
    )
    trust = TrustAssessment(
        package_name="hallucinated-package-xyz",
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.UNRESOLVED,
        identity_verified=True,
        registry_verified=False,
    )

    decision = policy_engine.evaluate(ident, trust, reg)
    assert decision.action == PolicyAction.BLOCK
    assert decision.risk_level == "HIGH"

def test_appeared_phantom_enforces_alert(policy_engine):
    ident = IdentityResolution(
        input_name="pre-registered-phantom",
        normalized_name="pre-registered-phantom",
        resolved_package="pre-registered-phantom",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name="pre-registered-phantom",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.FOUND,
        release_count=1,
        latest_version="0.0.1",
    )
    trust = TrustAssessment(
        package_name="pre-registered-phantom",
        ecosystem=Ecosystem.PYPI,
        level=TrustLevel.VERIFIED,
        identity_verified=True,
        registry_verified=True,
    )
    phantom = PhantomRecord(
        package_name="pre-registered-phantom",
        ecosystem=Ecosystem.PYPI,
        current_state=PhantomState.APPEARED,
        previous_state=PhantomState.NOT_FOUND,
    )

    decision = policy_engine.evaluate(ident, trust, reg, phantom_record=phantom)
    assert decision.action == PolicyAction.ALERT
    assert decision.risk_level == "CRITICAL"
    assert decision.requires_human_review is True
