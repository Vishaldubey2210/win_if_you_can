"""
Scenario E: Registry Network Timeout -> Gate Action: HOLD / REVIEW (Fail-Safe)
Network timeouts MUST NEVER be treated as missing packages.
"""
import asyncio
from unittest.mock import AsyncMock
from slopguard.core.models import Ecosystem, ExtractedDependency, PolicyAction, RegistryEvidence, RegistryStatus
from slopguard.core.scanner import ScannerService

async def run_scenario():
    scanner = ScannerService()
    # Inject Timeout response
    scanner.pypi_adapter.verify_package = AsyncMock(
        return_value=RegistryEvidence(
            package_name="unresponsive-pkg",
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.TIMEOUT,
            error_message="Registry request timed out after 5000ms",
        )
    )

    dep = ExtractedDependency(name="unresponsive-pkg", ecosystem=Ecosystem.PYPI)
    result = await scanner.scan_dependencies([dep], source_label="scenario_e")
    evaluated = result.dependencies[0]
    print(f"Scenario E Target: {dep.name}")
    print(f"Registry Status: {evaluated.registry.status.value}")
    print(f"Verdict: {evaluated.decision.action.value} (Expected: HOLD)")
    print(f"Requires Human Review: {evaluated.decision.requires_human_review}")
    print(f"Reasons: {evaluated.decision.reasons}")
    assert evaluated.decision.action == PolicyAction.HOLD
    assert evaluated.decision.requires_human_review is True
    return result

if __name__ == "__main__":
    asyncio.run(run_scenario())
