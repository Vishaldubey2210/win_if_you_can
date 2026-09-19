from __future__ import annotations
import difflib
import re
from typing import List, Optional
from slopguard.core.models import Ecosystem, EvaluatedDependency, PolicyAction
from slopguard.identity.resolver import PYPI_IMPORT_TO_PACKAGE
from slopguard.repair.models import PatchProposal, RepairCandidate, RescanValidation
from slopguard.trust.typosquat import TyposquatDetector

# Known modern stdlib alternatives for older/excessive libraries
STDLIB_ALTERNATIVES = {
    "pytz": "zoneinfo",
    "simplejson": "json",
    "mock": "unittest.mock",
    "pathlib2": "pathlib",
    "six": "builtins",
    "future": "builtins",
}


class RepairEngine:
    """
    Contextual dependency repair engine.
    Generates verified candidate replacements, produces clean diff patches,
    and enforces the mandatory RESCAN loop before any repair is accepted.
    """

    def __init__(self) -> None:
        self.typosquat_detector = TyposquatDetector()

    def generate_candidates(
        self,
        dependency_name: str,
        ecosystem: Ecosystem,
        context_snippet: Optional[str] = None,
    ) -> List[RepairCandidate]:
        candidates: List[RepairCandidate] = []
        clean_name = dependency_name.strip().lower()

        # 1. Check Standard Library Modern Alternatives
        if clean_name in STDLIB_ALTERNATIVES:
            stdlib_alt = STDLIB_ALTERNATIVES[clean_name]
            candidates.append(
                RepairCandidate(
                    candidate_package=stdlib_alt,
                    original_dependency=dependency_name,
                    ecosystem=ecosystem,
                    confidence=0.98,
                    compatibility_score=0.95,
                    is_stdlib_alternative=True,
                    reason=f"Standard library module '{stdlib_alt}' directly provides modern functionality without external dependencies.",
                    evidence_notes=["Standard library modern replacement"],
                )
            )

        # 2. Check High-Confidence Import Alias Graph
        if clean_name in PYPI_IMPORT_TO_PACKAGE:
            canonical_pkg = PYPI_IMPORT_TO_PACKAGE[clean_name]
            candidates.append(
                RepairCandidate(
                    candidate_package=canonical_pkg,
                    original_dependency=dependency_name,
                    ecosystem=ecosystem,
                    confidence=0.99,
                    compatibility_score=1.0,
                    is_stdlib_alternative=False,
                    reason=f"Import name '{dependency_name}' corresponds to official registry package '{canonical_pkg}'.",
                    evidence_notes=[f"Alias mapping: {dependency_name} -> {canonical_pkg}"],
                )
            )

        # 3. Check Typosquat / Homoglyph Similarities to Top Packages
        typo_match = self.typosquat_detector.check(dependency_name, ecosystem)
        if typo_match:
            candidates.append(
                RepairCandidate(
                    candidate_package=typo_match.similar_package,
                    original_dependency=dependency_name,
                    ecosystem=ecosystem,
                    confidence=typo_match.confidence,
                    compatibility_score=0.90,
                    is_stdlib_alternative=False,
                    reason=f"Detected high similarity to genuine popular package '{typo_match.similar_package}' ({typo_match.reason}).",
                    evidence_notes=[typo_match.reason],
                )
            )

        # Sort candidates by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def propose_patch(
        self,
        code: str,
        old_import: str,
        candidate: RepairCandidate,
    ) -> PatchProposal:
        """
        Creates a contextual patch replacing the old import with candidate package.
        Produces unified diff.
        """
        replacement = candidate.candidate_package
        # Pattern replacing exact module name in import statements
        pattern_import = re.compile(rf"\bimport\s+{re.escape(old_import)}\b")
        pattern_from = re.compile(rf"\bfrom\s+{re.escape(old_import)}\b")

        patched = pattern_import.sub(f"import {replacement}", code)
        patched = pattern_from.sub(f"from {replacement}", patched)

        # Generate diff
        old_lines = code.splitlines(keepends=True)
        new_lines = patched.splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile="original.py",
                tofile="patched.py",
                lineterm="",
            )
        )
        diff_str = "\n".join(diff_lines)

        return PatchProposal(
            original_code=code,
            patched_code=patched,
            original_import=old_import,
            replacement_import=replacement,
            diff=diff_str,
            candidate=candidate,
        )

    async def rescan_and_validate(
        self,
        proposal: PatchProposal,
        scanner_service,
        language: str = "python",
    ) -> RescanValidation:
        """
        MANDATORY RESCAN LOOP:
        PATCH -> RESCAN -> VERIFY
        A repair is never accepted unless rescanning passes policy!
        """
        try:
            rescan_result = await scanner_service.scan_code(
                content=proposal.patched_code,
                language=language,
                file_path="<patched_code>",
            )
        except Exception as exc:
            return RescanValidation(
                success=False,
                rescan_verdict=PolicyAction.BLOCK,
                reasons=[f"Rescan parsing failed with error: {exc}"],
                remaining_blocked_count=1,
            )

        blocked_count = rescan_result.summary.blocked_count
        reasons = []

        if blocked_count == 0:
            overall_verdict = PolicyAction.ALLOW
            success = True
            reasons.append("Rescan validated: all dependencies in patched code approved by policy gate.")
        else:
            overall_verdict = PolicyAction.BLOCK
            success = False
            reasons.append(f"Rescan failed: {blocked_count} dependency(ies) remain blocked in patched code.")

        return RescanValidation(
            success=success,
            rescan_verdict=overall_verdict,
            reasons=reasons,
            remaining_blocked_count=blocked_count,
        )
