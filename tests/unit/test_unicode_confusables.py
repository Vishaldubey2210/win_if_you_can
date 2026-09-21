import pytest
from slopguard.core.models import Ecosystem
from slopguard.trust.typosquat import TyposquatDetector, normalize_confusables

def test_normalize_cyrillic_homoglyphs():
    # Cyrillic 'у' (U+0443) in 'numpу'
    cyrillic_numpy = "nump\u0443"
    norm, had_homoglyphs = normalize_confusables(cyrillic_numpy)
    assert had_homoglyphs is True
    assert norm == "numpy"

    # Cyrillic 'е' (U+0435) in 'requеsts'
    cyrillic_requests = "requ\u0435sts"
    norm_req, had_homoglyphs_req = normalize_confusables(cyrillic_requests)
    assert had_homoglyphs_req is True
    assert norm_req == "requests"

def test_detect_homoglyph_attack():
    detector = TyposquatDetector()

    # Cyrillic lookalike for 'numpy'
    candidate = "nump\u0443"
    res = detector.check(candidate, Ecosystem.PYPI)
    assert res is not None
    assert res.similar_package == "numpy"
    assert "homoglyph" in res.reason.lower()
    assert res.confidence == 1.0

    # Cyrillic lookalike for 'requests'
    candidate_req = "requ\u0435sts"
    res_req = detector.check(candidate_req, Ecosystem.PYPI)
    assert res_req is not None
    assert res_req.similar_package == "requests"
    assert "homoglyph" in res_req.reason.lower()

def test_legitimate_ascii_not_flagged_as_homoglyph():
    detector = TyposquatDetector()
    assert detector.check("requests", Ecosystem.PYPI) is None
    assert detector.check("numpy", Ecosystem.PYPI) is None


def test_ast_extractor_captures_actual_cyrillic_character():
    """
    Proves the Python AST extractor preserves the actual Cyrillic U+0443 character
    from the source import token — it is NOT silently normalised to ASCII before extraction.

    This is critical: the homoglyph demo source MUST contain the real confusable byte
    in the extracted dependency name so the TyposquatDetector can identify it.
    """
    from slopguard.extraction.python_ast import PythonASTExtractor

    # This is the EXACT source that the UI loads in the Homoglyph Attack demo.
    # The import contains Cyrillic SMALL LETTER U (U+0443), not Latin y (U+0079).
    homoglyph_source = (
        "# Homoglyph Attack Demo\n"
        "# The import below uses Cyrillic '\u0443' (U+0443) not Latin 'y' (U+0079)\n"
        "import nump\u0443  # CONFUSABLE: final char U+0443\n"
        "import requests\n"
    )

    extractor = PythonASTExtractor()
    deps = extractor.extract(homoglyph_source, file_path="homoglyph_demo.py")

    # Should extract nump\u0443 and requests (not os/sys)
    names = [d.name for d in deps]
    assert len(deps) == 2, f"Expected 2 deps, got {len(deps)}: {names}"

    nump_dep = next((d for d in deps if "nump" in d.name), None)
    assert nump_dep is not None, "No nump* dependency found"

    # The ACTUAL Cyrillic character must be in the extracted name
    assert nump_dep.name == "nump\u0443", (
        f"Extracted name must be 'nump\\u0443', got {repr(nump_dep.name)}"
    )
    assert ord(nump_dep.name[-1]) == 0x0443, (
        f"Last char must be Cyrillic U+0443, got U+{ord(nump_dep.name[-1]):04X}"
    )

    # Confirm that it is NOT identical to the ASCII string 'numpy'
    assert nump_dep.name != "numpy", "Extracted name must NOT be 'numpy' — confusable must be preserved"

    # Now confirm the typosquat detector sees the homoglyph
    detector = TyposquatDetector()
    result = detector.check(nump_dep.name, Ecosystem.PYPI)
    assert result is not None, "TyposquatDetector must fire on extracted name"
    assert "homoglyph" in result.reason.lower()
    assert result.similar_package == "numpy"
    assert result.confidence == 1.0


def test_full_pipeline_homoglyph_demo_source():
    """
    End-to-end integration test for the Homoglyph Attack demo.

    Uses the FastAPI TestClient to POST the exact source code that the UI loads
    when clicking 'Load Homoglyph Attack', then verifies:
    1. The extracted token preserves Cyrillic U+0443
    2. The typosquat signal fires with 'homoglyph' in the reason
    3. The policy decision is BLOCK
    4. The evidence includes the similar_package == 'numpy'
    """
    from fastapi.testclient import TestClient
    from slopguard.api.app import app
    from slopguard.core.models import PolicyAction

    # EXACT source as produced by the UI's loadSampleCode('homoglyph')
    # Cyrillic у (U+0443) is the last character of 'nump\u0443'
    homoglyph_source = (
        "# Homoglyph Attack Demo\n"
        "# The import below uses Cyrillic '\u0443' (U+0443) not Latin 'y' (U+0079)\n"
        "# They look identical in monospace: nump\u0443 vs numpy\n"
        "import nump\u0443  # \u26a0 CONFUSABLE: final char is U+0443 (Cyrillic \u0443), not U+0079 (Latin y)\n"
        "import requests\n"
    )

    # Prove the source token is real Unicode — not ASCII
    assert "nump\u0443" in homoglyph_source, "Source must contain Cyrillic nump\u0443"
    # The import statement specifically must use the confusable, not the ASCII name
    import_lines = [l for l in homoglyph_source.splitlines() if l.startswith("import nump")]
    assert len(import_lines) == 1, f"Expected exactly one 'import nump*' line, got: {import_lines}"
    import_name = import_lines[0].split()[1]  # "nump\u0443"
    assert import_name.startswith("nump\u0443"), (
        f"Import must be 'nump\u0443' (Cyrillic), not {repr(import_name)}"
    )

    client = TestClient(app)
    resp = client.post(
        "/api/v1/scan",
        json={
            "content": homoglyph_source,
            "language": "python",
            "scenario": "HOMOGLYPH ATTACK",
            "source_label": "homoglyph_demo.py",
        },
    )
    assert resp.status_code == 200, f"Scan failed: {resp.text}"
    data = resp.json()

    assert data["scenario"] == "HOMOGLYPH ATTACK"

    nump_results = [d for d in data["dependencies"] if "nump" in d["extracted"]["name"]]
    assert len(nump_results) == 1, f"Expected 1 nump* dep, got {len(nump_results)}"
    nump = nump_results[0]

    # 1. Extracted name must contain the actual Cyrillic character
    extracted_name = nump["extracted"]["name"]
    assert extracted_name == "nump\u0443", (
        f"Extracted name must be 'nump\\u0443', got {repr(extracted_name)}"
    )
    assert ord(extracted_name[-1]) == 0x0443, (
        f"Last char must be U+0443, got U+{ord(extracted_name[-1]):04X}"
    )

    # 2. Typosquat/homoglyph evidence must be present
    ts = nump["trust"]["typosquat_details"]
    assert ts is not None, "typosquat_details must be set for homoglyph attack"
    assert "homoglyph" in ts["reason"].lower(), f"reason must mention homoglyph: {ts['reason']}"
    assert ts["similar_package"] == "numpy", f"similar_package must be 'numpy', got {ts['similar_package']}"
    assert ts["confidence"] == 1.0, f"confidence must be 1.0, got {ts['confidence']}"

    # 3. Policy decision must be BLOCK
    action = nump["decision"]["action"]
    assert action == PolicyAction.BLOCK.value, f"Expected BLOCK, got {action}"
