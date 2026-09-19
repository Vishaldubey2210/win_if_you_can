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
