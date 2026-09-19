import pytest
from datetime import datetime, timezone, timedelta
from slopguard.core.models import Ecosystem, RegistryEvidence, RegistryStatus
from slopguard.evidence.models import ProvenanceSignal, SecurityAdvisory
from slopguard.trust.signals import ReleaseSignalAnalyzer

def test_release_signal_analyzer():
    now = datetime.now(timezone.utc)

    # 1. Established package with multiple releases and repo
    reg_established = RegistryEvidence(
        package_name="flask",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.FOUND,
        release_count=35,
        first_release_time=now - timedelta(days=3000),
        latest_release_time=now - timedelta(days=120),
        repository_url="https://github.com/pallets/flask",
    )
    sig_est = ReleaseSignalAnalyzer.analyze(reg_established)
    assert sig_est.is_new_package is False
    assert sig_est.is_brand_new_release is False
    assert sig_est.has_repository is True
    assert sig_est.total_releases == 35

    # 2. Newly published package with single release and no repo
    reg_new = RegistryEvidence(
        package_name="brand-new-suspicious-pkg",
        ecosystem=Ecosystem.PYPI,
        status=RegistryStatus.FOUND,
        release_count=1,
        first_release_time=now - timedelta(days=2),
        latest_release_time=now - timedelta(days=2),
    )
    sig_new = ReleaseSignalAnalyzer.analyze(reg_new)
    assert sig_new.is_new_package is True
    assert sig_new.has_repository is False
    assert any("new package" in f.lower() for f in sig_new.flags)

    # 3. Active CRITICAL advisory
    advs = [
        SecurityAdvisory(
            advisory_id="GHSA-crit-0001",
            summary="Arbitrary code execution",
            severity="CRITICAL",
        )
    ]
    sig_adv = ReleaseSignalAnalyzer.analyze(reg_established, advisories=advs)
    assert sig_adv.advisories_count == 1
    assert sig_adv.highest_advisory_severity == "CRITICAL"
