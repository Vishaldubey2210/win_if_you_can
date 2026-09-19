import pytest
from unittest.mock import AsyncMock
from slopguard.core.scanner import ScannerService
from slopguard.core.models import Ecosystem, ExtractedDependency, RegistryStatus, RegistryEvidence


@pytest.mark.asyncio
async def test_audit_logging_and_reconstruction(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    scanner = ScannerService(audit_log_path=str(log_file))

    # Mock pypi adapter for determinism
    scanner.pypi_adapter.verify_package = AsyncMock(
        return_value=RegistryEvidence(
            package_name="phantom-fake-xyz",
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.NOT_FOUND,
        )
    )
    scanner.osv_adapter.query_advisories = AsyncMock(return_value=([], False))

    res = await scanner.scan_dependencies(
        [ExtractedDependency(name="phantom-fake-xyz", ecosystem=Ecosystem.PYPI)],
        source_label="audit_test",
    )

    dep = res.dependencies[0]
    assert dep.decision.action.value == "BLOCK"

    # Verify audit logger captured events
    events = scanner.audit_logger.list_events(package="phantom-fake-xyz")
    assert len(events) > 0
    event_types = [e.event_type.value for e in events]
    assert "dependency_extracted" in event_types
    assert "identity_resolved" in event_types
    assert "registry_checked" in event_types
    assert "policy_evaluated" in event_types
    assert "installation_blocked" in event_types

    # Test complete decision reconstruction
    recon = scanner.audit_logger.reconstruct("phantom-fake-xyz", evaluated_dep=dep)
    assert recon is not None
    assert recon.package == "phantom-fake-xyz"
    assert recon.verdict == "BLOCK"
    assert recon.risk_level == "HIGH"
    assert len(recon.audit_events) == len(events)
    assert any("not found" in r.lower() or "missing" in r.lower() or "unresolved" in r.lower() for r in recon.reasons)
