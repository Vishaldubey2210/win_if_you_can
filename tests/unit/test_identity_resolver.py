import pytest
from slopguard.identity.resolver import IdentityResolver
from slopguard.core.models import Ecosystem, ExtractedDependency, IdentityStatus

def test_alias_resolution():
    resolver = IdentityResolver()

    # cv2 -> opencv-python
    dep = ExtractedDependency(name="cv2", ecosystem=Ecosystem.PYPI)
    res = resolver.resolve(dep)
    assert res.status == IdentityStatus.ALIASED
    assert res.resolved_package == "opencv-python"
    assert res.is_stdlib is False

    # PIL -> pillow
    dep = ExtractedDependency(name="PIL", ecosystem=Ecosystem.PYPI)
    res = resolver.resolve(dep)
    assert res.status == IdentityStatus.ALIASED
    assert res.resolved_package == "pillow"

    # sklearn -> scikit-learn
    dep = ExtractedDependency(name="sklearn", ecosystem=Ecosystem.PYPI)
    res = resolver.resolve(dep)
    assert res.status == IdentityStatus.ALIASED
    assert res.resolved_package == "scikit-learn"

def test_stdlib_resolution():
    resolver = IdentityResolver()
    dep = ExtractedDependency(name="sys", ecosystem=Ecosystem.PYPI)
    res = resolver.resolve(dep)
    assert res.status == IdentityStatus.STDLIB
    assert res.is_stdlib is True

def test_pep503_normalization():
    resolver = IdentityResolver()
    dep = ExtractedDependency(name="My_Custom.Package", ecosystem=Ecosystem.PYPI)
    res = resolver.resolve(dep)
    assert res.resolved_package == "my-custom-package"
