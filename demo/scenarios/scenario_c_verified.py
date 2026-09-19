"""
Scenario C: Established, Verified Package with High Provenance -> Gate Action: ALLOW
"""
import asyncio
from slopguard.core.models import Ecosystem, ExtractedDependency, PolicyAction
from slopguard.core.scanner import ScannerService

async def run_scenario():
    scanner = ScannerService()
    dep = ExtractedDependency(name="fastapi", ecosystem=Ecosystem.PYPI)
    result = await scanner.scan_dependencies([dep], source_label="scenario_c")
    evaluated = result.dependencies[0]
    print(f"Scenario C Target: {dep.name}")
    print(f"Verdict: {evaluated.decision.action.value} (Expected: ALLOW)")
    print(f"Risk: {evaluated.decision.risk_level}")
    print(f"Trust Level: {evaluated.trust.level.value}")
    assert evaluated.decision.action == PolicyAction.ALLOW
    return result

if __name__ == "__main__":
    asyncio.run(run_scenario())
