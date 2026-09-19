import pytest
from slopguard.trust.typosquat import TyposquatDetector
from slopguard.core.models import Ecosystem

def test_detect_typosquat_pypi():
    detector = TyposquatDetector()

    # requets -> requests (distance 1)
    res = detector.check("requets", Ecosystem.PYPI)
    assert res is not None
    assert res.similar_package == "requests"
    assert res.distance == 1

    # nump -> numpy (distance 1)
    res = detector.check("nump", Ecosystem.PYPI)
    assert res is not None
    assert res.similar_package == "numpy"

    # exact match is NOT a typosquat
    assert detector.check("requests", Ecosystem.PYPI) is None
    assert detector.check("numpy", Ecosystem.PYPI) is None

def test_detect_typosquat_npm():
    detector = TyposquatDetector()

    # lodahs -> lodash
    res = detector.check("lodahs", Ecosystem.NPM)
    assert res is not None
    assert res.similar_package == "lodash"
    assert res.distance == 1
