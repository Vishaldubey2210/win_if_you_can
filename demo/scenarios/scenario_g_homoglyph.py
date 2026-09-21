"""
Scenario G: Unicode Confusable Homoglyph Attack -> BLOCK

Demonstrates a real homoglyph attack where a package identifier contains
Cyrillic SMALL LETTER U (U+0443) in place of Latin 'y' (U+0079).

The source token: import nump\u0443
looks visually identical to: import numpy
in most monospace fonts — but contains a non-ASCII confusable character.

SLOPGUARD detects this via its Unicode confusable normalisation pipeline
in the TyposquatDetector, and the DeterministicPolicyEngine blocks it.
"""
import asyncio
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from slopguard.core.models import Ecosystem, ExtractedDependency, PolicyAction
from slopguard.core.scanner import ScannerService


# The Python source that contains the homoglyph import.
# The final character of 'nump\u0443' is Cyrillic SMALL LETTER U (U+0443), NOT Latin 'y' (U+0079).
# They are visually identical in monospace fonts.
HOMOGLYPH_SOURCE = (
    "# Homoglyph Attack Demo\n"
    "# The import below uses Cyrillic '\u0443' (U+0443) not Latin 'y' (U+0079)\n"
    "# They look identical in monospace: nump\u0443 vs numpy\n"
    "import nump\u0443  # \u26a0 CONFUSABLE: final char is U+0443 (Cyrillic \u0443), not U+0079 (Latin y)\n"
    "import requests\n"
)


async def run_scenario():
    scanner = ScannerService()

    print("=== SCENARIO G: Unicode Confusable Homoglyph Attack ===")
    print()
    print("Source code loaded (repr):")
    print(repr(HOMOGLYPH_SOURCE))
    print()
    print("Source code rendered:")
    print(HOMOGLYPH_SOURCE)
    print()

    # Verify the actual source token contains the confusable character
    assert "\u0443" in HOMOGLYPH_SOURCE, "Source must contain Cyrillic U+0443"
    nump_u_line = [line for line in HOMOGLYPH_SOURCE.splitlines() if "nump" in line and "import" in line][0]
    nump_name = "nump\u0443"
    assert nump_name in nump_u_line, f"Expected {repr(nump_name)} in import line {repr(nump_u_line)}"
    assert ord(nump_name[-1]) == 0x0443, (
        f"Last char of import name must be U+0443 (Cyrillic у), got U+{ord(nump_name[-1]):04X}"
    )
    print(f"VERIFIED: import name={repr(nump_name)}, last char U+{ord(nump_name[-1]):04X} (Cyrillic у)")
    print()

    result = await scanner.scan_code(
        content=HOMOGLYPH_SOURCE,
        language="python",
        file_path="scenario_g_homoglyph.py",
        scenario="HOMOGLYPH ATTACK",
    )

    print("=== SCAN RESULTS ===")
    for dep in result.dependencies:
        print(f"Package: {repr(dep.extracted.name)}")
        print(f"  Unicode chars: " + " ".join(
            f"U+{ord(c):04X}" for c in dep.extracted.name
        ))
        print(f"  Identity: {dep.identity.resolved_package} (status={dep.identity.status.value})")
        print(f"  Decision: {dep.decision.action.value}")
        print(f"  Risk: {dep.decision.risk_level}")
        if dep.trust.typosquat_details:
            ts = dep.trust.typosquat_details
            print(f"  Homoglyph detected: {ts.reason}")
            print(f"  Confidence: {ts.confidence}")
            print(f"  Similar to: {ts.similar_package}")
        print()

    # Assertions
    nump_deps = [d for d in result.dependencies if "nump" in d.extracted.name]
    assert len(nump_deps) == 1, "Expected exactly one nump* dependency"
    nump_dep = nump_deps[0]

    # 1. Extractor captured the actual Cyrillic character
    assert ord(nump_dep.extracted.name[-1]) == 0x0443, (
        f"Extractor must capture Cyrillic U+0443, got U+{ord(nump_dep.extracted.name[-1]):04X}"
    )

    # 2. Typosquat detector fired with homoglyph reason
    assert nump_dep.trust.typosquat_details is not None, "Typosquat details must be set"
    assert "homoglyph" in nump_dep.trust.typosquat_details.reason.lower(), (
        "Reason must mention 'homoglyph'"
    )
    assert nump_dep.trust.typosquat_details.similar_package == "numpy", (
        "Similar package must be 'numpy'"
    )
    assert nump_dep.trust.typosquat_details.confidence == 1.0, (
        "Homoglyph confidence must be 1.0"
    )

    # 3. Policy gate blocked it
    assert nump_dep.decision.action == PolicyAction.BLOCK, (
        f"nump\u0443 must be BLOCK, got {nump_dep.decision.action}"
    )

    print("ALL ASSERTIONS PASSED")
    print(f"Scenario: {result.scenario}")
    print(f"Summary: {result.summary}")
    return result


if __name__ == "__main__":
    asyncio.run(run_scenario())
