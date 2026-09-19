"""
Scenario B: Import Alias Resolution -> Resolved Identity & Safe Evaluation
"""
import asyncio
from slopguard.core.models import Ecosystem, ExtractedDependency
from slopguard.core.scanner import ScannerService

async def run_scenario():
    scanner = ScannerService()
    dep = ExtractedDependency(name="cv2", ecosystem=Ecosystem.PYPI)
    result = await scanner.scan_dependencies([dep], source_label="scenario_b")
    evaluated = result.dependencies[0]
    print(f"Scenario B Target: {dep.name}")
    print(f"Resolved Canonical Package: {evaluated.identity.resolved_package}")
    print(f"Verdict: {evaluated.decision.action.value}")
    print(f"Suggested Fix: {evaluated.decision.suggested_fix}")
    assert evaluated.identity.resolved_package == "opencv-python"
    return result

if __name__ == "__main__":
    asyncio.run(run_scenario())
