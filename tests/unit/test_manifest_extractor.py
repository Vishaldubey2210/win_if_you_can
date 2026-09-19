import pytest
from slopguard.extraction.manifest import ManifestExtractor
from slopguard.core.models import Ecosystem

def test_parse_requirements_txt():
    content = """
# Production requirements
requests>=2.28.0
numpy==1.24.0
fastapi[all]>=0.100.0; python_version >= '3.10'
--extra-index-url https://custom.repo/pypi
-r base.txt
pyyaml # comment after package
"""
    deps = ManifestExtractor.parse_requirements_txt(content)
    names = {d.name: d for d in deps}

    assert "requests" in names
    assert names["requests"].version_constraint == ">=2.28.0"
    assert "numpy" in names
    assert names["numpy"].version_constraint == "==1.24.0"
    assert "fastapi" in names
    assert "pyyaml" in names
    assert len(deps) == 4

def test_parse_package_json():
    content = """
{
  "name": "my-app",
  "dependencies": {
    "react": "^18.2.0",
    "axios": "~1.4.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
"""
    deps = ManifestExtractor.parse_package_json(content)
    names = {d.name: d for d in deps}

    assert "react" in names
    assert "axios" in names
    assert "typescript" in names
    assert len(deps) == 3
