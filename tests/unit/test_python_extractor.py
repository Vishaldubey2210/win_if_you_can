import pytest
from slopguard.extraction.python_ast import PythonASTExtractor
from slopguard.core.models import Ecosystem

def test_extract_standard_and_third_party():
    code = """
import os
import sys
from pathlib import Path
import requests
import numpy as np
from PIL import Image
from . import local_helper
from ..models import User
"""
    extractor = PythonASTExtractor()
    deps = extractor.extract(code)

    names = {d.name: d for d in deps}

    # Stdlib checks
    assert "os" in names
    assert names["os"].is_stdlib is True
    assert names["sys"].is_stdlib is True
    assert names["pathlib"].is_stdlib is True

    # Third-party checks
    assert "requests" in names
    assert names["requests"].is_stdlib is False
    assert names["numpy"].is_stdlib is False
    assert names["PIL"].is_stdlib is False

    # Relative imports
    rel_imports = [d for d in deps if d.is_relative]
    assert len(rel_imports) == 2

def test_extract_syntax_error():
    bad_code = "def invalid_python(: pass"
    extractor = PythonASTExtractor()
    with pytest.raises(ValueError, match="Syntax error"):
        extractor.extract(bad_code)
