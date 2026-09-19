"""
Scenario A: Missing / Hallucinated Package -> Gate Action: BLOCK
"""
import asyncio
from slopguard.core.models import Ecosystem, ExtractedDependency, PolicyAction
from slopguard.core.scanner import ScannerService

async def run_scenario():
    scanner = ScannerService()
    dep = ExtractedDependency(name="langchain-hyper-fast-auth-helper-v9", ecosystem=Ecosystem.PYPI)
    result = await scanner.scan_dependencies([dep], source_label="scenario_a")
    decision = result.dependencies[0].decision
    print(f"Scenario A Target: {dep.name}")
    print(f"Verdict: {decision.action.value} (Expected: BLOCK)")
    print(f"Risk: {decision.risk_level}")
    print(f"Reasons: {decision.reasons}")
    assert decision.action == PolicyAction.BLOCK
    return result

if __name__ == "__main__":
    asyncio.run(run_scenario())
