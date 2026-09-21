import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from slopguard.api.app import app
from slopguard.core.models import Ecosystem, PolicyAction

client = TestClient(app)

INDEX_HTML_PATH = Path(__file__).parents[2] / "slopguard" / "api" / "static" / "index.html"


def test_scenario_state_clean_sample():
    """Requirement A: Load Clean Sample -> source changes, scenario=CLEAN SAMPLE, scan preserves label."""
    clean_code = "import os\nimport sys\nimport requests\nimport numpy as np"
    resp = client.post(
        "/api/v1/scan",
        json={
            "content": clean_code,
            "language": "python",
            "scenario": "CLEAN SAMPLE",
            "source_label": "clean_sample.py",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["scenario"] == "CLEAN SAMPLE"
    assert data["summary"]["total_extracted"] == 4
    # os and sys are stdlib (ALLOW), requests & numpy valid (ALLOW)
    for dep in data["dependencies"]:
        assert dep["decision"]["action"] == PolicyAction.ALLOW.value


def test_scenario_state_homoglyph_attack():
    """Requirement B: Load Homoglyph Attack -> scenario=HOMOGLYPH ATTACK, scan preserves label."""
    homoglyph_code = "# Cyrillic 'у' (U+0443)\nimport nump\u0443\nimport requests"
    resp = client.post(
        "/api/v1/scan",
        json={
            "content": homoglyph_code,
            "language": "python",
            "scenario": "HOMOGLYPH ATTACK",
            "source_label": "homoglyph.py",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["scenario"] == "HOMOGLYPH ATTACK"
    assert data["summary"]["total_extracted"] == 2
    # numpу homoglyph must be blocked / quarantined
    actions = [d["decision"]["action"] for d in data["dependencies"]]
    assert PolicyAction.BLOCK.value in actions or PolicyAction.HOLD.value in actions


def test_scenario_state_phantom_dependency():
    """Requirement 5: Phantom demo -> scenario=PHANTOM DEPENDENCY, scan preserves label."""
    phantom_code = "import os\nimport sys\nimport cv2\nimport requests\nimport langchain_fastapi_agent_optimizer"
    resp = client.post(
        "/api/v1/scan",
        json={
            "content": phantom_code,
            "language": "python",
            "scenario": "PHANTOM DEPENDENCY",
            "source_label": "phantom.py",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["scenario"] == "PHANTOM DEPENDENCY"
    assert data["summary"]["total_extracted"] == 5
    phantom_deps = [d for d in data["dependencies"] if d["extracted"]["name"] == "langchain_fastapi_agent_optimizer"]
    assert len(phantom_deps) == 1
    assert phantom_deps[0]["decision"]["action"] == PolicyAction.BLOCK.value


def test_scenario_state_custom_input():
    """Requirement C: Custom input -> scenario=CUSTOM INPUT."""
    custom_code = "import math\nimport json\nimport requests"
    resp = client.post(
        "/api/v1/scan",
        json={
            "content": custom_code,
            "language": "python",
            "scenario": "CUSTOM INPUT",
            "source_label": "custom.py",
        },
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["scenario"] == "CUSTOM INPUT"
    assert data["summary"]["total_extracted"] == 3


def test_scenario_state_determinism_repeated_runs():
    """Requirement E: Run the same input twice -> extracted dependencies and verdicts remain deterministic."""
    sample_code = "import os\nimport sys\nimport requests\nimport numpy as np"
    
    resp1 = client.post(
        "/api/v1/scan",
        json={"content": sample_code, "language": "python", "scenario": "CLEAN SAMPLE"},
    )
    resp2 = client.post(
        "/api/v1/scan",
        json={"content": sample_code, "language": "python", "scenario": "CLEAN SAMPLE"},
    )

    data1 = resp1.json()
    data2 = resp2.json()

    assert data1["scenario"] == data2["scenario"] == "CLEAN SAMPLE"
    assert data1["summary"]["total_extracted"] == data2["summary"]["total_extracted"]
    assert data1["summary"]["allowed_count"] == data2["summary"]["allowed_count"]
    assert data1["summary"]["blocked_count"] == data2["summary"]["blocked_count"]

    extracted_names_1 = [d["extracted"]["name"] for d in data1["dependencies"]]
    extracted_names_2 = [d["extracted"]["name"] for d in data2["dependencies"]]
    assert extracted_names_1 == extracted_names_2

    verdicts_1 = [d["decision"]["action"] for d in data1["dependencies"]]
    verdicts_2 = [d["decision"]["action"] for d in data2["dependencies"]]
    assert verdicts_1 == verdicts_2


def test_frontend_scenario_ui_elements():
    """Verify HTML UI contains all explicit scenario indicators and deterministic mechanisms."""
    assert INDEX_HTML_PATH.exists()
    html = INDEX_HTML_PATH.read_text(encoding="utf-8")

    # 1. Indicator near source editor
    assert 'ACTIVE SCENARIO:' in html
    assert 'id="active-scenario-badge"' in html

    # 2. Buttons for deterministic scenario loading
    assert 'onclick="loadSampleCode(\'clean\')"' in html
    assert 'onclick="loadSampleCode(\'homoglyph\')"' in html
    assert 'onclick="loadSampleCode(\'phantom\')"' in html

    # 3. Verdict stream scenario label
    assert 'id="verdict-scenario-badge"' in html

    # 4. Input listener for CUSTOM INPUT
    assert "setScenario('CUSTOM INPUT')" in html

    # 5. LocalStorage deterministic persistence
    assert "localStorage.getItem('slopguard_scan_scenario')" in html
    assert "localStorage.setItem('slopguard_scan_scenario'" in html
