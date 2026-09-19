from __future__ import annotations
from typing import Dict, List, Optional, Set
from slopguard.core.models import Ecosystem, TyposquatCandidate

# Curated list of high-value targets commonly typosquatted
POPULAR_PYPI_PACKAGES: Set[str] = {
    "requests", "numpy", "pandas", "urllib3", "six", "setuptools", "wheel",
    "pip", "boto3", "botocore", "certifi", "idna", "charset-normalizer",
    "typing-extensions", "python-dateutil", "s3transfer", "pydantic",
    "packaging", "scipy", "scikit-learn", "torch", "matplotlib", "pyyaml",
    "click", "flask", "django", "fastapi", "uvicorn", "httpx", "aiohttp",
    "pytest", "black", "flake8", "pillow", "tqdm", "protobuf", "cryptography",
    "jinja2", "markupsafe", "attrs", "beautifulsoup4", "psycopg2", "redis",
    "celery", "gunicorn", "rich", "colorama", "virtualenv", "openpyxl",
    "selenium", "playwright", "transformers", "huggingface-hub", "langchain",
    "openai", "anthropic", "google-generativeai"
}

POPULAR_NPM_PACKAGES: Set[str] = {
    "react", "react-dom", "lodash", "chalk", "commander", "express",
    "axios", "moment", "typescript", "debug", "tslib", "async", "fs-extra",
    "glob", "vue", "rxjs", "uuid", "webpack", "babel-core", "core-js",
    "next", "dotenv", "cross-env", "inquirer", "semver", "mkdirp",
    "body-parser", "cors", "yargs", "winston", "mongoose", "tailwindcss",
    "postcss", "eslint", "prettier", "jest", "vite", "nodemon"
}


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Damerau-Levenshtein distance between two strings,
    accounting for insertions, deletions, substitutions, and transpositions.
    """
    d: Dict[tuple, int] = {}
    len1, len2 = len(s1), len(s2)

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]


class TyposquatDetector:
    """
    Detects potential typosquatting or combative naming attempts
    against popular open-source packages.
    """

    def __init__(self) -> None:
        self.pypi_targets = POPULAR_PYPI_PACKAGES
        self.npm_targets = POPULAR_NPM_PACKAGES

    def check(self, candidate_name: str, ecosystem: Ecosystem) -> Optional[TyposquatCandidate]:
        name = candidate_name.strip().lower()
        targets = self.pypi_targets if ecosystem == Ecosystem.PYPI else self.npm_targets

        # If it's an exact match to a popular package, it is that package, not a squat
        if name in targets:
            return None

        best_match: Optional[str] = None
        min_dist: int = 999

        for target in targets:
            # Skip comparisons if length difference is too large to be an accidental typo
            if abs(len(name) - len(target)) > 2:
                continue

            dist = damerau_levenshtein_distance(name, target)

            # A distance of 1 or 2 on packages with length >= 4 indicates strong similarity
            if dist in (1, 2) and min(len(name), len(target)) >= 4:
                if dist < min_dist:
                    min_dist = dist
                    best_match = target

        if best_match:
            max_len = max(len(name), len(best_match))
            similarity_ratio = round(1.0 - (min_dist / max_len), 3)
            confidence = 0.95 if min_dist == 1 else 0.80
            return TyposquatCandidate(
                target_package=name,
                similar_package=best_match,
                distance=min_dist,
                similarity_ratio=similarity_ratio,
                confidence=confidence,
                reason=(
                    f"Name '{name}' is within edit distance {min_dist} "
                    f"of popular package '{best_match}' (similarity {similarity_ratio * 100:.1f}%)"
                ),
            )

        return None
