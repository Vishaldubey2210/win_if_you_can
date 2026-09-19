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
from slopguard.evidence.models import SecurityAdvisory
from slopguard.policy.engine import DeterministicPolicyEngine
from slopguard.trust.evaluator import TrustEvaluator

@pytest.fixture
def evaluator():
    return TrustEvaluator()

@pytest.fixture
def policy():
    return DeterministicPolicyEngine()

def test_homoglyph_attack_blocks_installation(evaluator, policy):
    # 'numpу' using Cyrillic 'у' (U+0443)
    cyrillic_numpy = "nump\u0443"
    ident = IdentityResolution(
        input_name=cyrillic_numpy,
        normalized_name=cyrillic_numpy,
        resolved_package=cyrillic_numpy,
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name=cyrillic_numpy,
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.FOUND,
        release_count=1,
    )

    trust = evaluator.evaluate(ident, reg)
    assert trust.has_typosquat_risk is True
    assert "homoglyph" in trust.typosquat_details.reason.lower()

    decision = policy.evaluate(ident, trust, reg)
    assert decision.action == PolicyAction.BLOCK
    assert decision.risk_level == "CRITICAL"
    assert "homoglyph" in decision.reasons[0].lower()

def test_critical_osv_advisory_blocks_installation(evaluator, policy):
    ident = IdentityResolution(
        input_name="known-vuln-lib",
        normalized_name="known-vuln-lib",
        resolved_package="known-vuln-lib",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name="known-vuln-lib",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.FOUND,
        release_count=10,
        repository_url="https://github.com/example/vuln",
    )
    advisories = [
        SecurityAdvisory(
            advisory_id="GHSA-9999-xxxx",
            summary="Critical Remote Code Execution in parser",
            severity="CRITICAL",
        )
    ]

    trust = evaluator.evaluate(ident, reg, advisories=advisories)
    assert trust.signals["release_signals"]["highest_advisory_severity"] == "CRITICAL"

    decision = policy.evaluate(ident, trust, reg)
    assert decision.action == PolicyAction.BLOCK
    assert decision.risk_level == "HIGH"
    assert "security advisory" in decision.reasons[0].lower()

def test_new_package_without_repo_triggers_hold(evaluator, policy):
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)

    ident = IdentityResolution(
        input_name="sketchy-brand-new-pkg",
        normalized_name="sketchy-brand-new-pkg",
        resolved_package="sketchy-brand-new-pkg",
        ecosystem=Ecosystem.PYPI,
        status=IdentityStatus.RESOLVED,
    )
    reg = RegistryEvidence(
        package_name="sketchy-brand-new-pkg",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.FOUND,
        release_count=1,
        first_release_time=now - timedelta(days=1),
        latest_release_time=now - timedelta(days=1),
        repository_url=None,  # No repository
    )

    trust = evaluator.evaluate(ident, reg)
    decision = policy.evaluate(ident, trust, reg)

    assert decision.action == PolicyAction.HOLD
    assert decision.requires_human_review is True
    assert any("newly published" in r.lower() for r in decision.reasons)
