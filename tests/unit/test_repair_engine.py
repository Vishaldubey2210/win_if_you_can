import pytest
from slopguard.core.models import Ecosystem
from slopguard.core.scanner import ScannerService
from slopguard.repair.engine import RepairEngine

@pytest.mark.asyncio
async def test_repair_engine_lifecycle(tmp_path):
    storage = tmp_path / "test_repair_phantoms.json"
    scanner = ScannerService(phantom_storage_path=str(storage))
    engine = RepairEngine()

    # 1. Typosquat repair
    candidates = engine.generate_candidates("requets", Ecosystem.PYPI)
    assert len(candidates) > 0
    assert candidates[0].candidate_package == "requests"

    # 2. Propose patch
    original_code = "import requets\ndef fetch(): pass\n"
    proposal = engine.propose_patch(original_code, "requets", candidates[0])
    assert "import requests" in proposal.patched_code
    assert "-import requets" in proposal.diff
    assert "+import requests" in proposal.diff

    # 3. Mandatory RESCAN Loop: Validate patched code through scanner
    rescan_val = await engine.rescan_and_validate(proposal, scanner, language="python")
    assert rescan_val.success is True
    assert rescan_val.remaining_blocked_count == 0

def test_repair_stdlib_alternative():
    engine = RepairEngine()
    candidates = engine.generate_candidates("pytz", Ecosystem.PYPI)
    assert any(c.candidate_package == "zoneinfo" for c in candidates)
    assert any(c.is_stdlib_alternative for c in candidates)
