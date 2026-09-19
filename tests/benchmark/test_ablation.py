import pytest
from slopguard.benchmark.ablation import AblationBenchmarkRunner


@pytest.mark.asyncio
async def test_ablation_ladder():
    runner = AblationBenchmarkRunner()
    results = await runner.run_full_ladder()

    assert len(results) >= 5
    levels = [r.level for r in results]
    assert "B0" in levels
    assert "B1" in levels
    assert "B2" in levels
    assert "B3" in levels
    assert "B5" in levels

    # Verify that B0 (naive regex) has lower accuracy than B5 (full control plane)
    b0 = next(r for r in results if r.level == "B0")
    b5 = next(r for r in results if r.level == "B5")

    # B0 must fail on aliases and comments, B5 must achieve 100% on the benchmark cases
    assert b0.accuracy_pct < b5.accuracy_pct
    assert b5.accuracy_pct == 100.0
