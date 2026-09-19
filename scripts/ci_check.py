#!/usr/bin/env python3
"""
SLOPGUARD CI/CD Automated Policy Gate Runner
Integrates into any CI pipeline (GitHub Actions, GitLab CI, CircleCI, Jenkins, etc.)
Exit Codes:
  0: SUCCESS (All dependencies ALLOWed, or policy requirements met)
  1: REVIEW REQUIRED (Dependencies on HOLD/REVIEW under strict policy)
  2: BLOCKED / FAILED (One or more dependencies BLOCKed or ALERT triggered)
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
from pathlib import Path
from slopguard.core.scanner import ScannerService
from slopguard.core.models import PolicyAction
from slopguard.policy.config import PolicyConfig, PolicyProfile


def main():
    parser = argparse.ArgumentParser(description="SLOPGUARD Pre-Install CI/CD Gate")
    parser.add_argument("target", help="File, manifest, or directory to scan")
    parser.add_argument("--profile", default="strict_ci", choices=["development", "strict_ci", "enterprise"], help="Policy profile")
    parser.add_argument("--fail-on-review", action="store_true", help="Fail with exit code 1 if any dependency requires review (HOLD)")
    parser.add_argument("--output-json", default=None, help="Save scan summary and verdicts to a JSON report file")

    args = parser.parse_args()

    prof_enum = PolicyProfile(args.profile.upper())
    policy_cfg = PolicyConfig.from_profile(prof_enum)
    scanner = ScannerService(policy_config=policy_cfg)

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(2)

    try:
        if target_path.is_dir():
            ignore_dirs = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache"}
            all_deps = []
            for item in target_path.rglob("*"):
                if any(ignored in item.parts for ignored in ignore_dirs):
                    continue
                if item.is_file():
                    fname = item.name.lower()
                    ext = item.suffix.lower()
                    if fname in ("requirements.txt", "pyproject.toml", "package.json") or ext in (".py", ".js", ".ts", ".jsx", ".tsx"):
                        try:
                            content = item.read_text(encoding="utf-8", errors="ignore")
                            lang = "requirements" if fname == "requirements.txt" else "pyproject" if fname == "pyproject.toml" else "package_json" if fname == "package.json" else "python" if ext == ".py" else "javascript" if ext in (".js", ".jsx") else "typescript"
                            all_deps.extend(scanner.extract_from_source(content, language=lang, file_path=str(item)))
                        except Exception:
                            continue
            result = asyncio.run(scanner.scan_dependencies(all_deps, source_label=str(target_path.resolve())))
        else:
            result = asyncio.run(scanner.scan_file(str(target_path)))
    except Exception as exc:
        print(f"SLOPGUARD CI Scan Error: {exc}", file=sys.stderr)
        sys.exit(2)

    if args.output_json:
        Path(args.output_json).write_text(result.model_dump_json(indent=2), encoding="utf-8")

    # Output CI summary table
    print("=" * 70)
    print("SLOPGUARD CI/CD FIREWALL GATE RESULT")
    print(f"Target: {args.target} | Profile: {args.profile.upper()}")
    print(f"Allowed: {result.summary.allowed_count} | Hold: {result.summary.hold_count} | Blocked: {result.summary.blocked_count} | Alerts: {result.summary.alert_count}")
    print("=" * 70)

    for dep in result.dependencies:
        status_tag = f"[{dep.decision.action.value}]"
        print(f"{status_tag:10} {dep.extracted.name:25} -> {dep.identity.resolved_package:25}")
        for r in dep.decision.reasons:
            print(f"           * {r}")

    # Enforce CI Gate Verdicts
    if result.summary.blocked_count > 0 or result.summary.alert_count > 0:
        print("\n[CI GATE FAILED] Dangerous or unverified dependencies blocked by policy.", file=sys.stderr)
        sys.exit(2)

    if result.summary.hold_count > 0 and (args.fail_on_review or args.profile.lower() == "strict_ci"):
        print("\n[CI GATE PENDING REVIEW] Dependencies in quarantine requiring human approval.", file=sys.stderr)
        sys.exit(1)

    print("\n[CI GATE PASSED] All dependencies verified and compliant with policy.")
    sys.exit(0)


if __name__ == "__main__":
    main()
