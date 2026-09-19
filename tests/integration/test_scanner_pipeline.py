import pytest
from slopguard.core.scanner import ScannerService
from slopguard.core.models import PolicyAction, RegistryStatus

@pytest.mark.asyncio
async def test_full_pipeline_scan(tmp_path):
    phantom_db = tmp_path / "test_phantoms.json"
    scanner = ScannerService(phantom_storage_path=str(phantom_db))

    sample_code = """
import os
import sys
import cv2
import definitely_nonexistent_hallucinated_pkg_123456
"""
    result = await scanner.scan_code(sample_code, language="python")

    assert len(result.dependencies) == 4
    deps_by_name = {d.extracted.name: d for d in result.dependencies}

    # os & sys
    assert deps_by_name["os"].decision.action == PolicyAction.ALLOW
    assert deps_by_name["os"].identity.is_stdlib is True
    assert deps_by_name["sys"].decision.action == PolicyAction.ALLOW

    # cv2 aliased to opencv-python
    cv2_dep = deps_by_name["cv2"]
    assert cv2_dep.identity.resolved_package == "opencv-python"
    assert cv2_dep.decision.action == PolicyAction.ALLOW
    assert cv2_dep.registry.status == RegistryStatus.FOUND

    # Hallucinated package
    hallucinated = deps_by_name["definitely_nonexistent_hallucinated_pkg_123456"]
    assert hallucinated.decision.action == PolicyAction.BLOCK
    assert hallucinated.registry.status == RegistryStatus.NOT_FOUND

    # Verify phantom recorded in memory
    saved_phantom = scanner.memory.get_record("definitely_nonexistent_hallucinated_pkg_123456", cv2_dep.identity.ecosystem)
    assert saved_phantom is not None
