"""
Scenario D: Registry HTTP 429 Rate Limiting -> Gate Action: HOLD / REVIEW (Fail-Safe)
Network or registry throttling MUST NEVER be converted to NOT_FOUND.
"""
import asyncio
from unittest.mock import AsyncMock
from slopguard.core.models import Ecosystem, ExtractedDependency, PolicyAction, RegistryEvidence, RegistryStatus
from slopguard.core.scanner import ScannerService

async def run_scenario():
    scanner = ScannerService()
    # Inject 429 Rate Limit response
    scanner.pypi_adapter.verify_package = AsyncMock(
        return_value=RegistryEvidence(
            package_name="throttled-lib",
            ecosystem=Ecosystem.PYPI,
            status=RegistryStatus.RATE_LIMITED,
            error_message="HTTP 429 Too Many Requests from registry endpoint",
        )
    )

    dep = ExtractedDependency(name="throttled-lib", ecosystem=Ecosystem.PYPI)
    result = await scanner.scan_dependencies([dep], source_label="scenario_d")
    evaluated = result.dependencies[0]
    print(f"Scenario D Target: {dep.name}")
    print(f"Registry Status: {evaluated.registry.status.value}")
    print(f"Verdict: {evaluated.decision.action.value} (Expected: HOLD)")
    print(f"Requires Human Review: {evaluated.decision.requires_human_review}")
    print(f"Reasons: {evaluated.decision.reasons}")
    assert evaluated.decision.action == PolicyAction.HOLD
    assert evaluated.decision.requires_human_review is True
    return result

if __name__ == "__main__":
    asyncio.run(run_scenario())
