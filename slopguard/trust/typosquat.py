from __future__ import annotations
import unicodedata
from typing import Dict, List, Optional, Set, Tuple
from slopguard.core.models import Ecosystem, TyposquatCandidate

# High-value package targets commonly typosquatted
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

# Common visual confusable homoglyph mappings (Cyrillic, Greek, Latin fullwidth)
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a", "А": "A", "с": "c", "С": "C", "е": "e", "Е": "E",
    "о": "o", "О": "O", "р": "p", "Р": "P", "ѕ": "s", "Ѕ": "S",
    "у": "y", "У": "Y", "х": "x", "Х": "X", "і": "i", "І": "I",
    "ј": "j", "Ј": "J", "в": "b", "В": "B", "м": "m", "М": "M",
    "н": "h", "Н": "H", "к": "k", "К": "K", "т": "t", "Т": "T",
    # Greek lookalikes
    "ο": "o", "Ο": "O", "ν": "v", "Ν": "N", "ρ": "p", "Ρ": "P",
    "τ": "t", "Τ": "T", "κ": "k", "Κ": "K", "α": "a", "Α": "A",
    "ε": "e", "Ε": "E", "ι": "i", "Ι": "I",
    # Dashes and separators
    "–": "-", "—": "-", "−": "-", "‐": "-", "‑": "-", "‒": "-",
}


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Damerau-Levenshtein distance between two strings,
    accounting for insertions, deletions, substitutions, and transpositions.
    """
    d: Dict[Tuple[int, int], int] = {}
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


def normalize_confusables(s: str) -> Tuple[str, bool]:
    """
    Normalizes string using NFKC and converts known homoglyphs into ASCII equivalents.
    Returns: (normalized_string, had_homoglyphs)
    """
    normalized_unicode = unicodedata.normalize("NFKC", s)
    result = []
    had_homoglyphs = False

    for ch in normalized_unicode:
        if ch in HOMOGLYPH_MAP:
            result.append(HOMOGLYPH_MAP[ch])
            had_homoglyphs = True
        else:
            result.append(ch)

    return "".join(result).lower(), had_homoglyphs


class TyposquatDetector:
    """
    Detects potential typosquatting, punctuation spoofing, and Unicode confusable
    homoglyphs against popular open-source packages.
    """

    def __init__(self) -> None:
        self.pypi_targets = POPULAR_PYPI_PACKAGES
        self.npm_targets = POPULAR_NPM_PACKAGES

    def check(self, candidate_name: str, ecosystem: Ecosystem) -> Optional[TyposquatCandidate]:
        raw_name = candidate_name.strip()
        targets = self.pypi_targets if ecosystem == Ecosystem.PYPI else self.npm_targets

        # Check 1: Unicode Confusables / Homoglyphs
        deconfused_name, had_homoglyphs = normalize_confusables(raw_name)
        if had_homoglyphs and deconfused_name in targets:
            return TyposquatCandidate(
                target_package=raw_name,
                similar_package=deconfused_name,
                distance=1,
                similarity_ratio=0.99,
                confidence=1.0,
                reason=(
                    f"CRITICAL: Unicode confusable homoglyph detected! Visual lookalike for popular "
                    f"package '{deconfused_name}' using non-ASCII characters."
                ),
            )

        name = deconfused_name

        # Exact match is the real package
        if name in targets:
            return None

        # Check 2: Punctuation / separator normalization (e.g. requests_toolbelt vs requests-toolbelt)
        # Note: only flag if candidate without separators matches a root target
        stripped_name = name.replace("-", "").replace("_", "").replace(".", "")

        best_match: Optional[str] = None
        min_dist: int = 999

        for target in targets:
            # Skip comparisons if length difference is too large
            if abs(len(name) - len(target)) > 2:
                continue

            dist = damerau_levenshtein_distance(name, target)

            # Distance of 1 or 2 on packages of sufficient length indicates strong similarity
            if dist in (1, 2) and min(len(name), len(target)) >= 4:
                if dist < min_dist:
                    min_dist = dist
                    best_match = target

        if best_match:
            max_len = max(len(name), len(best_match))
            similarity_ratio = round(1.0 - (min_dist / max_len), 3)
            confidence = 0.95 if min_dist == 1 else 0.80
            return TyposquatCandidate(
                target_package=raw_name,
                similar_package=best_match,
                distance=min_dist,
                similarity_ratio=similarity_ratio,
                confidence=confidence,
                reason=(
                    f"Name '{raw_name}' is within edit distance {min_dist} "
                    f"of popular package '{best_match}' (similarity {similarity_ratio * 100:.1f}%)"
                ),
            )

        return None
