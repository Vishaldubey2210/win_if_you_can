"""
Scenario F: Previously Unresolved Phantom Dependency Later Appears -> Gate Action: ALERT
State transition NOT_FOUND -> APPEARED signals a critical dependency confusion /
phantom hijacking risk, requiring mandatory security review.
"""
import asyncio
from unittest.mock import AsyncMock
from slopguard.core.models import Ecosystem, ExtractedDependency, PhantomState, PolicyAction, RegistryEvidence, RegistryStatus
from slopguard.core.scanner import ScannerService

async def run_scenario():
    scanner = ScannerService()

    # Step 1 (T0): Package is missing (NOT_FOUND)
    scanner.pypi_adapter.verify_package = AsyncMock(
        return_value=RegistryEvidence(
            package_name="target-phantom-corp",
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.NOT_FOUND,
        )
    )
    dep = ExtractedDependency(name="target-phantom-corp", ecosystem=Ecosystem.PYPI)
    res_t0 = await scanner.scan_dependencies([dep], source_label="scenario_f_t0")
    record_t0 = scanner.memory.get_record("target-phantom-corp", Ecosystem.PYPI)
    assert record_t0.current_state == PhantomState.NOT_FOUND
    print(f"T0 State for 'target-phantom-corp': {record_t0.current_state.value}")

    # Step 2 (T1): Attacker registers package; it now appears on PyPI (FOUND)
    scanner.pypi_adapter.verify_package = AsyncMock(
        return_value=RegistryEvidence(
            package_name="target-phantom-corp",
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.FOUND,
            latest_version="0.0.1",
            release_count=1,
        )
    )
    res_t1 = await scanner.scan_dependencies([dep], source_label="scenario_f_t1")
    evaluated_t1 = res_t1.dependencies[0]
    record_t1 = scanner.memory.get_record("target-phantom-corp", Ecosystem.PYPI)

    print(f"T1 State for 'target-phantom-corp': {record_t1.current_state.value} (Expected: APPEARED)")
    print(f"Verdict: {evaluated_t1.decision.action.value} (Expected: ALERT)")
    print(f"Reasons: {evaluated_t1.decision.reasons}")

    assert record_t1.current_state == PhantomState.APPEARED
    assert evaluated_t1.decision.action == PolicyAction.ALERT
    return res_t1

if __name__ == "__main__":
    asyncio.run(run_scenario())
