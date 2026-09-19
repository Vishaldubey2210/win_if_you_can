import asyncio
import time
import pytest
from slopguard.core.models import Ecosystem, ExtractedDependency, PolicyAction, RegistryStatus
from slopguard.core.scanner import ScannerService

BENCHMARK_CORPUS = {
    "REAL": [
        ("requests", Ecosystem.PYPI, PolicyAction.ALLOW),
        ("numpy", Ecosystem.PYPI, PolicyAction.ALLOW),
        ("express", Ecosystem.NPM, PolicyAction.ALLOW),
        ("lodash", Ecosystem.NPM, PolicyAction.ALLOW),
    ],
    "PHANTOM": [
        ("fastapi-pydantic-validator-ai-pro", Ecosystem.PYPI, PolicyAction.BLOCK),
        ("pytorch-neural-optimizer-phantom", Ecosystem.PYPI, PolicyAction.BLOCK),
        ("react-super-agent-optimizer-nonexistent", Ecosystem.NPM, PolicyAction.BLOCK),
    ],
    "TRICKY": [
        ("cv2", Ecosystem.PYPI, PolicyAction.ALLOW),
        ("PIL", Ecosystem.PYPI, PolicyAction.ALLOW),
        ("yaml", Ecosystem.PYPI, PolicyAction.ALLOW),
        ("sys", Ecosystem.PYPI, PolicyAction.ALLOW),
    ],
    "ADVERSARIAL": [
        ("requets", Ecosystem.PYPI, PolicyAction.BLOCK),  # Typosquat (or BLOCK because 404 + squat)
        ("nump\u0443", Ecosystem.PYPI, PolicyAction.BLOCK),  # Cyrillic homoglyph
    ]
}

@pytest.mark.asyncio
async def test_benchmark_suite(tmp_path):
    storage = tmp_path / "bench_phantoms.json"
    scanner = ScannerService(phantom_storage_path=str(storage))

    results = {}
    latencies = []

    for category, test_cases in BENCHMARK_CORPUS.items():
        correct = 0
        total = len(test_cases)

        for pkg_name, eco, expected_action in test_cases:
            t0 = time.perf_counter()
            dep = ExtractedDependency(name=pkg_name, ecosystem=eco)
            scan_res = await scanner.scan_dependencies([dep], source_label="benchmark")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)

            actual_action = scan_res.dependencies[0].decision.action
            # Both BLOCK or HOLD are acceptable containment actions for ADVERSARIAL
            if category == "ADVERSARIAL":
                if actual_action in (PolicyAction.BLOCK, PolicyAction.HOLD):
                    correct += 1
            elif actual_action == expected_action:
                correct += 1

        accuracy = (correct / total) * 100.0
        results[category] = {
            "correct": correct,
            "total": total,
            "accuracy": accuracy,
        }

    # Verify high accuracy on real corpus
    assert results["REAL"]["accuracy"] == 100.0
    assert results["PHANTOM"]["accuracy"] == 100.0
    assert results["TRICKY"]["accuracy"] == 100.0
    assert results["ADVERSARIAL"]["accuracy"] == 100.0
