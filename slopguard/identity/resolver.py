from __future__ import annotations
import re
from typing import Dict, Optional, Tuple
from slopguard.core.models import Ecosystem, ExtractedDependency, IdentityResolution, IdentityStatus
from slopguard.extraction.python_ast import get_python_stdlib_names
from slopguard.extraction.javascript import NODE_BUILTINS

# Canonical high-confidence PyPI import-to-package name mappings
PYPI_IMPORT_TO_PACKAGE: Dict[str, str] = {
    "cv2": "opencv-python",
    "pil": "pillow",
    "yaml": "pyyaml",
    "sklearn": "scikit-learn",
    "dateutil": "python-dateutil",
    "bs4": "beautifulsoup4",
    "jwt": "pyjwt",
    "serial": "pyserial",
    "magic": "python-magic",
    "dotenv": "python-dotenv",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "openssl": "pyopenssl",
    "crypto": "pycryptodome",
    "cryptography": "cryptography",
    "git": "gitpython",
    "google": "protobuf",
    "attr": "attrs",
    "fitz": "pymupdf",
    "opengl": "pyopengl",
    "usb": "pyusb",
    "cups": "pycups",
    "wx": "wxpython",
    "gi": "pygobject",
    "vlc": "python-vlc",
    "pylab": "matplotlib",
    "playwright": "playwright",
    "telegram": "python-telegram-bot",
    "discord": "discord.py",
    "slack_sdk": "slack-sdk",
    "redis": "redis",
    "pymongo": "pymongo",
    "psycopg2": "psycopg2-binary",
    "mysqldb": "mysqlclient",
    "sqlalchemy": "sqlalchemy",
    "pydantic": "pydantic",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "httpx": "httpx",
    "requests": "requests",
    "aiohttp": "aiohttp",
}


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: replace [-_.]+ with a single '-' and lowercase."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_npm_name(name: str) -> str:
    """npm package names are lowercase, with scope prefix retained."""
    trimmed = name.strip()
    if trimmed.startswith("@"):
        parts = trimmed.split("/", 1)
        if len(parts) == 2:
            return f"@{parts[0][1:].lower()}/{parts[1].lower()}"
    return trimmed.lower()


class IdentityResolver:
    """
    Resolves extracted dependency identifiers into canonical package identities,
    handling PEP 503 normalization, stdlib catalogs, and known import-to-package aliases.
    """

    def __init__(self) -> None:
        self.py_stdlib = get_python_stdlib_names()
        self.node_builtins = NODE_BUILTINS

    def resolve(self, dep: ExtractedDependency) -> IdentityResolution:
        raw_name = dep.name.strip()
        ecosystem = dep.ecosystem

        # Check standard library
        if ecosystem == Ecosystem.PYPI and (dep.is_stdlib or raw_name.lower() in self.py_stdlib):
            return IdentityResolution(
                input_name=raw_name,
                normalized_name=raw_name.lower(),
                resolved_package=raw_name,
                ecosystem=Ecosystem.PYPI,
                status=IdentityStatus.STDLIB,
                confidence=1.0,
                is_stdlib=True,
                evidence_notes=["Identified as Python standard library module"],
            )

        if ecosystem == Ecosystem.NPM and (dep.is_stdlib or raw_name.lower() in self.node_builtins):
            return IdentityResolution(
                input_name=raw_name,
                normalized_name=raw_name.lower(),
                resolved_package=raw_name,
                ecosystem=Ecosystem.NPM,
                status=IdentityStatus.STDLIB,
                confidence=1.0,
                is_stdlib=True,
                evidence_notes=["Identified as Node.js built-in module"],
            )

        # Handle PyPI
        if ecosystem == Ecosystem.PYPI:
            norm_name = normalize_pypi_name(raw_name)
            lower_raw = raw_name.lower()

            # Check known alias mapping
            if lower_raw in PYPI_IMPORT_TO_PACKAGE:
                canonical = PYPI_IMPORT_TO_PACKAGE[lower_raw]
                return IdentityResolution(
                    input_name=raw_name,
                    normalized_name=normalize_pypi_name(canonical),
                    resolved_package=canonical,
                    ecosystem=Ecosystem.PYPI,
                    status=IdentityStatus.ALIASED,
                    confidence=0.98,
                    is_stdlib=False,
                    evidence_notes=[
                        f"Resolved via high-confidence import alias: '{raw_name}' -> '{canonical}'"
                    ],
                )

            # Direct PEP 503 normalized package
            return IdentityResolution(
                input_name=raw_name,
                normalized_name=norm_name,
                resolved_package=norm_name,
                ecosystem=Ecosystem.PYPI,
                status=IdentityStatus.RESOLVED,
                confidence=0.95,
                is_stdlib=False,
                evidence_notes=[f"Normalized to PEP 503 canonical name: '{norm_name}'"],
            )

        # Handle NPM
        if ecosystem == Ecosystem.NPM:
            norm_npm = normalize_npm_name(raw_name)
            return IdentityResolution(
                input_name=raw_name,
                normalized_name=norm_npm,
                resolved_package=norm_npm,
                ecosystem=Ecosystem.NPM,
                status=IdentityStatus.RESOLVED,
                confidence=0.95,
                is_stdlib=False,
                evidence_notes=[f"Normalized to npm package name: '{norm_npm}'"],
            )

        # Fallback unknown ecosystem
        return IdentityResolution(
            input_name=raw_name,
            normalized_name=raw_name.lower(),
            resolved_package=raw_name,
            ecosystem=Ecosystem.UNKNOWN,
            status=IdentityStatus.AMBIGUOUS,
            confidence=0.5,
            is_stdlib=False,
            evidence_notes=["Unknown ecosystem; unable to establish canonical identity mapping"],
        )
