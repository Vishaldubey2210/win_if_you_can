from __future__ import annotations
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from slopguard.core.models import (
    Ecosystem,
    EvaluatedDependency,
    ExtractedDependency,
    PolicyAction,
    RegistryStatus,
)
from slopguard.core.scanner import ScannerService

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(version="0.2.0", prog_name="slopguard")
def cli():
    """SLOPGUARD: AI Dependency Control Plane & Supply-Chain Firewall."""
    pass


@cli.command("scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--profile", "-p", type=click.Choice(["development", "strict_ci", "enterprise"], case_sensitive=False), default=None, help="Policy profile to evaluate.")
@click.option("--json-output", "--json", is_flag=True, help="Output results in JSON format.")
def scan_cmd(target: str, profile: Optional[str], json_output: bool):
    """Scan a source code file, manifest, or directory for dependencies and enforce security gate."""
    from slopguard.policy.config import PolicyConfig, PolicyProfile
    policy_cfg = None
    if profile:
        prof_enum = PolicyProfile(profile.upper())
        policy_cfg = PolicyConfig.from_profile(prof_enum)

    scanner = ScannerService(policy_config=policy_cfg)
    path = Path(target)

    try:
        if path.is_dir():
            # Scan directory recursively
            ignore_dirs = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".idea", ".vscode"}
            extracted_all = []
            for item in path.rglob("*"):
                if any(ignored in item.parts for ignored in ignore_dirs):
                    continue
                if item.is_file():
                    fname = item.name.lower()
                    ext = item.suffix.lower()
                    if fname in ("requirements.txt", "pyproject.toml", "package.json") or ext in (".py", ".js", ".ts", ".jsx", ".tsx"):
                        try:
                            content = item.read_text(encoding="utf-8", errors="ignore")
                            lang = "requirements" if fname == "requirements.txt" else "pyproject" if fname == "pyproject.toml" else "package_json" if fname == "package.json" else "python" if ext == ".py" else "javascript" if ext in (".js", ".jsx") else "typescript"
                            extracted_all.extend(scanner.extract_from_source(content, language=lang, file_path=str(item)))
                        except Exception:
                            continue
            result = asyncio.run(scanner.scan_dependencies(extracted_all, source_label=str(path.resolve())))
        else:
            result = asyncio.run(scanner.scan_file(str(path)))
    except Exception as exc:
        err_console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        sys.exit(1)

    if json_output:
        click.echo(result.model_dump_json(indent=2))
        if result.summary.blocked_count > 0:
            sys.exit(2)
        return

    # Beautiful Rich Terminal Output
    console.print(Panel.fit(
        f"[bold cyan]SLOPGUARD AI Dependency Firewall[/bold cyan]\n"
        f"Target: [bold]{target}[/bold] | Profile: [magenta]{scanner.policy_engine.config.profile.value.upper()}[/magenta] | Duration: [green]{result.summary.duration_ms}ms[/green]",
        title="Security Scan Complete",
        border_style="cyan"
    ))

    table = Table(title="Dependency Control Plane Verdicts", show_lines=True)
    table.add_column("Import / Specifier", style="bold")
    table.add_column("Canonical Package", style="magenta")
    table.add_column("Registry Status", justify="center")
    table.add_column("Gate Verdict", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Reason / Evidence")

    has_block = False

    for dep in result.dependencies:
        # Verdict color
        if dep.decision.action == PolicyAction.ALLOW:
            verdict_text = Text("ALLOW", style="bold green")
        elif dep.decision.action == PolicyAction.HOLD:
            verdict_text = Text("HOLD", style="bold yellow")
        elif dep.decision.action == PolicyAction.BLOCK:
            verdict_text = Text("BLOCK", style="bold red")
            has_block = True
        elif dep.decision.action == PolicyAction.ALERT:
            verdict_text = Text("ALERT", style="bold white on red")
            has_block = True
        else:
            verdict_text = Text(dep.decision.action.value)

        # Risk color
        risk_style = "green"
        if dep.decision.risk_level == "HIGH":
            risk_style = "red"
        elif dep.decision.risk_level == "MEDIUM":
            risk_style = "yellow"
        elif dep.decision.risk_level == "CRITICAL":
            risk_style = "bold white on red"
        risk_text = Text(dep.decision.risk_level, style=risk_style)

        reg_status = dep.registry.status.value if dep.registry else ("STDLIB" if dep.identity.is_stdlib else "N/A")
        reasons_summary = "\n".join(dep.decision.reasons)
        if dep.decision.suggested_fix:
            reasons_summary += f"\n[bold cyan]Fix:[/bold cyan] {dep.decision.suggested_fix}"

        table.add_row(
            dep.extracted.name,
            dep.identity.resolved_package,
            reg_status,
            verdict_text,
            risk_text,
            reasons_summary,
        )

    console.print(table)

    summary_panel = (
        f"[green]Allowed: {result.summary.allowed_count}[/green] | "
        f"[yellow]Hold/Review: {result.summary.hold_count}[/yellow] | "
        f"[red]Blocked: {result.summary.blocked_count}[/red] | "
        f"[bold red]Alerts: {result.summary.alert_count}[/bold red] | "
        f"Stdlib: {result.summary.stdlib_count}"
    )
    console.print(Panel(summary_panel, title="Scan Summary", border_style="dim"))

    if has_block:
        sys.exit(1)


@cli.command("verify")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True, help="Output results in JSON format.")
def verify_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Verify a single package directly against registry evidence and security policy."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    adapter = scanner.pypi_adapter if eco == Ecosystem.PYPI else scanner.npm_adapter

    evidence = asyncio.run(adapter.verify_package(package_name))

    if json_output:
        click.echo(evidence.model_dump_json(indent=2))
        return

    status_color = "green" if evidence.status.value == "FOUND" else "red"
    console.print(Panel.fit(
        f"Package: [bold]{evidence.package_name}[/bold] ({evidence.ecosystem.value})\n"
        f"Status: [bold {status_color}]{evidence.status.value}[/]\n"
        f"Latency: {evidence.latency_ms:.1f}ms | Releases: {evidence.release_count}\n"
        f"Latest Version: {evidence.latest_version or 'N/A'}\n"
        f"Repository: {evidence.repository_url or 'N/A'}",
        title="Registry Verification Evidence",
        border_style="blue"
    ))


@cli.command("advisories")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--version", "-v", default=None, help="Specific version to query")
@click.option("--json-output", "--json", is_flag=True)
def advisories_cmd(package_name: str, ecosystem: str, version: Optional[str], json_output: bool):
    """Query live vulnerability advisories from OSV (Open Source Vulnerabilities)."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    advs, record = asyncio.run(scanner.osv_adapter.query_advisories(package_name, eco, version=version))

    if json_output:
        data = {
            "package": package_name,
            "ecosystem": eco.value,
            "version": version,
            "advisories": [a.model_dump(mode="json") for a in advs],
            "record": record.model_dump(mode="json"),
        }
        click.echo(json.dumps(data, indent=2))
        return

    if not advs:
        console.print(f"[bold green]No active advisories found on OSV for {package_name} ({eco.value}).[/bold green]")
        return

    table = Table(title=f"OSV Vulnerability Advisories: {package_name}", show_lines=True)
    table.add_column("Advisory ID", style="bold red")
    table.add_column("Severity", justify="center")
    table.add_column("Summary")
    table.add_column("Affected Versions")

    for a in advs:
        sev_color = "red" if a.severity in ("CRITICAL", "HIGH") else "yellow"
        table.add_row(
            a.advisory_id,
            Text(a.severity, style=f"bold {sev_color}"),
            a.summary,
            ", ".join(a.affected_versions) if a.affected_versions else "All versions",
        )

    console.print(table)


@cli.command("trust")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True)
def trust_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Inspect multi-dimensional release trust assessment and provenance."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    adapter = scanner.pypi_adapter if eco == Ecosystem.PYPI else scanner.npm_adapter

    dep = ExtractedDependency(name=package_name, ecosystem=eco)
    identity = scanner.identity_resolver.resolve(dep)

    async def get_trust():
        registry = await adapter.verify_package(identity.resolved_package)
        advs, _ = await scanner.osv_adapter.query_advisories(identity.resolved_package, eco, version=registry.latest_version)
        prov = scanner.provenance_extractor.extract(registry)
        return scanner.trust_evaluator.evaluate(identity, registry, advs, prov), registry

    assessment, registry = asyncio.run(get_trust())

    if json_output:
        click.echo(assessment.model_dump_json(indent=2))
        return

    level_color = "green" if assessment.level.value == "VERIFIED" else "yellow" if assessment.level.value == "REVIEW" else "red"
    panel_text = (
        f"Target Package: [bold]{assessment.package_name}[/bold] ({assessment.ecosystem.value})\n"
        f"Trust Level: [bold {level_color}]{assessment.level.value}[/]\n"
        f"Identity: {'Verified' if assessment.identity_verified else 'Unverified'} | "
        f"Registry: {'Verified' if assessment.registry_verified else 'Unverified'}\n"
        f"Typosquat Risk: {'DETECTED' if assessment.has_typosquat_risk else 'None'}\n\n"
        f"[bold underline]Signals:[/bold underline]\n"
    )
    for k, v in assessment.signals.items():
        if k != "release_signals":
            panel_text += f"  - {k}: {v}\n"

    panel_text += f"\n[bold underline]Reasons:[/bold underline]\n"
    for r in assessment.reasons:
        panel_text += f"  • {r}\n"

    console.print(Panel(panel_text, title="Trust Assessment", border_style="cyan"))


@cli.command("graph")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True)
def graph_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Query Evidence Graph relationships for a package."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM

    # Ingest package into graph
    async def build():
        adapter = scanner.pypi_adapter if eco == Ecosystem.PYPI else scanner.npm_adapter
        dep = ExtractedDependency(name=package_name, ecosystem=eco)
        identity = scanner.identity_resolver.resolve(dep)
        registry = await adapter.verify_package(identity.resolved_package)
        advs, _ = await scanner.osv_adapter.query_advisories(identity.resolved_package, eco, version=registry.latest_version)
        prov = scanner.provenance_extractor.extract(registry)
        trust = scanner.trust_evaluator.evaluate(identity, registry, advs, prov)
        decision = scanner.policy_engine.evaluate(identity, trust, registry)
        eval_dep = EvaluatedDependency(
            extracted=dep,
            identity=identity,
            registry=registry,
            trust=trust,
            decision=decision,
        )
        scanner.evidence_graph.ingest_evaluated_dependency(eval_dep, advs, prov)

    asyncio.run(build())

    releases = scanner.evidence_graph.get_package_releases(package_name, eco)
    repo = scanner.evidence_graph.get_package_repository(package_name, eco)
    advs = scanner.evidence_graph.get_package_advisories(package_name, eco)
    prov = scanner.evidence_graph.get_package_provenance(package_name, eco)

    if json_output:
        data = {
            "package": package_name,
            "ecosystem": eco.value,
            "releases": [r.model_dump(mode="json") for r in releases],
            "repository": repo.model_dump(mode="json") if repo else None,
            "advisories": [a.model_dump(mode="json") for a in advs],
            "provenance": prov.model_dump(mode="json") if prov else None,
        }
        click.echo(json.dumps(data, indent=2))
        return

    table = Table(title=f"Evidence Graph Relationships: {package_name}", show_lines=True)
    table.add_column("Relation Edge", style="bold cyan")
    table.add_column("Target Node")
    table.add_column("Type", justify="center")

    if repo:
        table.add_row("HOSTED_AT", repo.label, repo.type.value)
    for r in releases:
        table.add_row("HAS_RELEASE", r.label, r.type.value)
    for a in advs:
        table.add_row("AFFECTED_BY", a.label, a.type.value)
    if prov:
        table.add_row("ATTESTED_BY", prov.label, prov.type.value)

    console.print(table)


@cli.command("phantom")
@click.argument("action", type=click.Choice(["list", "clear"], case_sensitive=False), default="list")
@click.option("--json-output", "--json", is_flag=True)
def phantom_cmd(action: str, json_output: bool):
    """Inspect the Temporal Phantom Watchlist."""
    scanner = ScannerService()
    phantoms = scanner.memory.list_phantoms()

    if json_output:
        click.echo(json.dumps([p.model_dump(mode="json") for p in phantoms], indent=2))
        return

    if not phantoms:
        console.print("[green]No unresolved phantoms in temporal watchlist.[/green]")
        return

    table = Table(title="Temporal Phantom Watchlist", show_lines=True)
    table.add_column("Package Name", style="bold")
    table.add_column("Ecosystem")
    table.add_column("Current State", justify="center")
    table.add_column("Observations", justify="right")
    table.add_column("First Seen")
    table.add_column("Transitions")

    for p in phantoms:
        state_style = "red" if p.current_state.value == "NOT_FOUND" else "bold white on red" if p.current_state.value == "APPEARED" else "yellow"
        trans_summary = " -> ".join([t.to_state.value for t in p.transitions]) if p.transitions else "Initial"
        table.add_row(
            p.package_name,
            p.ecosystem.value,
            Text(p.current_state.value, style=state_style),
            str(p.occurrence_count),
            p.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            trans_summary,
        )

    console.print(table)


@cli.command("evidence")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True)
def evidence_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Retrieve full structured evidence (registry, advisories, provenance) for a package."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    adapter = scanner.pypi_adapter if eco == Ecosystem.PYPI else scanner.npm_adapter

    async def gather():
        reg = await adapter.verify_package(package_name)
        advs, _ = await scanner.osv_adapter.query_advisories(package_name, eco, version=reg.latest_version)
        prov = scanner.provenance_extractor.extract(reg)
        return reg, advs, prov

    reg, advs, prov = asyncio.run(gather())

    if json_output:
        data = {
            "package": package_name,
            "ecosystem": eco.value,
            "registry": reg.model_dump(mode="json"),
            "advisories": [a.model_dump(mode="json") for a in advs],
            "provenance": prov.model_dump(mode="json"),
        }
        click.echo(json.dumps(data, indent=2))
        return

    console.print(Panel.fit(
        f"[bold cyan]Package Evidence Dossier[/bold cyan]\n"
        f"Package: [bold]{package_name}[/bold] ({eco.value})\n"
        f"Registry Status: [bold {'green' if reg.status.value == 'FOUND' else 'red'}]{reg.status.value}[/]\n"
        f"Releases: {reg.release_count} | Latest: {reg.latest_version or 'N/A'}\n"
        f"Repository: {reg.repository_url or 'N/A'}\n"
        f"Security Advisories: [bold {'red' if advs else 'green'}]{len(advs)}[/]\n"
        f"Cryptographic Provenance: {'Verified' if prov.has_provenance else 'None'}",
        title="Evidence Summary",
        border_style="cyan"
    ))


@cli.command("history")
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--json-output", "--json", is_flag=True)
def history_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Inspect temporal phantom transitions and audit events for a package."""
    scanner = ScannerService()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM
    record = scanner.memory.get_record(package_name, eco)
    events = scanner.audit_logger.list_events(package=package_name)

    if json_output:
        data = {
            "package": package_name,
            "ecosystem": eco.value,
            "phantom_record": record.model_dump(mode="json") if record else None,
            "audit_events": [e.model_dump(mode="json") for e in events],
        }
        click.echo(json.dumps(data, indent=2))
        return

    if not record and not events:
        console.print(f"[yellow]No historical observations or audit events found for '{package_name}'.[/yellow]")
        return

    if record:
        p_text = (
            f"Package: [bold]{record.package_name}[/bold] ({record.ecosystem.value})\n"
            f"Current State: [bold]{record.current_state.value}[/bold]\n"
            f"Observation Count: {record.occurrence_count}\n"
            f"First Seen: {record.first_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Last Seen: {record.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"State Transitions: {len(record.transitions)}"
        )
        console.print(Panel(p_text, title="Temporal Phantom Memory", border_style="cyan"))

    if events:
        table = Table(title=f"Audit Trail Events: {package_name}", show_lines=True)
        table.add_column("Timestamp", style="dim")
        table.add_column("Event Type", style="bold cyan")
        table.add_column("Actor")
        table.add_column("Action", justify="center")

        for ev in events:
            action_style = "green" if ev.action == "ALLOW" else "red" if ev.action == "BLOCK" else "yellow"
            table.add_row(
                ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                ev.event_type.value,
                ev.actor,
                Text(ev.action or "-", style=action_style),
            )
        console.print(table)


@cli.command("repair")
@click.argument("dependency")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"], case_sensitive=False), default="pypi")
@click.option("--file", "-f", "code_file", type=click.Path(exists=True), help="Source code file to propose patch for.")
@click.option("--json-output", "--json", is_flag=True)
def repair_cmd(dependency: str, ecosystem: str, code_file: Optional[str], json_output: bool):
    """Propose candidate repairs and safe diff patches for hallucinated or unresolved dependencies."""
    from slopguard.repair.engine import RepairEngine
    engine = RepairEngine()
    eco = Ecosystem.PYPI if ecosystem.lower() == "pypi" else Ecosystem.NPM

    candidates = engine.generate_candidates(dependency, eco)

    proposal = None
    if code_file and candidates:
        code_content = Path(code_file).read_text(encoding="utf-8", errors="ignore")
        proposal = engine.propose_patch(code_content, dependency, candidates[0])

    if json_output:
        data = {
            "dependency": dependency,
            "ecosystem": eco.value,
            "candidates": [c.model_dump(mode="json") for c in candidates],
            "proposal": proposal.model_dump(mode="json") if proposal else None,
        }
        click.echo(json.dumps(data, indent=2))
        return

    if not candidates:
        console.print(f"[yellow]No verified repair candidates found for '{dependency}'.[/yellow]")
        return

    table = Table(title=f"Repair Candidates for '{dependency}'", show_lines=True)
    table.add_column("Rank", justify="center")
    table.add_column("Candidate Package", style="bold green")
    table.add_column("Confidence", justify="right")
    table.add_column("Reason / Source")

    for idx, c in enumerate(candidates, 1):
        table.add_row(
            str(idx),
            c.candidate_package,
            f"{c.confidence * 100:.0f}%",
            c.reason,
        )
    console.print(table)

    if proposal:
        console.print(Panel(
            proposal.diff,
            title=f"Proposed Diff Patch ({Path(code_file).name})",
            border_style="green"
        ))


@cli.command("rescan")
@click.argument("target_file", type=click.Path(exists=True))
@click.option("--language", "-l", default="python", help="Language of the patched code.")
@click.option("--profile", "-p", type=click.Choice(["development", "strict_ci", "enterprise"], case_sensitive=False), default="strict_ci")
@click.option("--json-output", "--json", is_flag=True)
def rescan_cmd(target_file: str, language: str, profile: str, json_output: bool):
    """Rescan a patched code file and enforce the mandatory RESCAN verification gate."""
    from slopguard.policy.config import PolicyConfig, PolicyProfile
    prof_enum = PolicyProfile(profile.upper())
    cfg = PolicyConfig.from_profile(prof_enum)
    scanner = ScannerService(policy_config=cfg)

    try:
        result = asyncio.run(scanner.scan_file(target_file))
    except Exception as exc:
        err_console.print(f"[bold red]Rescan failed:[/bold red] {exc}")
        sys.exit(2)

    success = result.summary.blocked_count == 0
    overall_action = PolicyAction.ALLOW if success else PolicyAction.BLOCK

    if json_output:
        data = {
            "file": target_file,
            "success": success,
            "verdict": overall_action.value,
            "blocked_count": result.summary.blocked_count,
            "summary": result.summary.model_dump(),
        }
        click.echo(json.dumps(data, indent=2))
        if not success:
            sys.exit(2)
        return

    status_color = "green" if success else "red"
    console.print(Panel.fit(
        f"File: [bold]{target_file}[/bold]\n"
        f"Rescan Verdict: [bold {status_color}]{overall_action.value}[/]\n"
        f"Blocked Dependencies: {result.summary.blocked_count} | Allowed: {result.summary.allowed_count}\n"
        f"Gate Status: {'[bold green]PASSED - Safe to apply[/]' if success else '[bold red]FAILED - Blocked dependencies remain[/]'}",
        title="Patch Rescan Validation Gate",
        border_style=status_color
    ))
    if not success:
        sys.exit(2)


@cli.command("policy")
@click.argument("action", type=click.Choice(["check", "simulate"], case_sensitive=False), default="check")
@click.option("--profile", "-p", type=click.Choice(["development", "strict_ci", "enterprise"], case_sensitive=False), default="strict_ci")
@click.option("--json-output", "--json", is_flag=True)
def policy_cmd(action: str, profile: str, json_output: bool):
    """Inspect or simulate Policy-as-Code profile and rule matrix."""
    from slopguard.policy.config import PolicyConfig, PolicyProfile
    prof_enum = PolicyProfile(profile.upper())
    cfg = PolicyConfig.from_profile(prof_enum)

    if json_output:
        click.echo(cfg.model_dump_json(indent=2))
        return

    table = Table(title=f"Policy-as-Code Profile: {prof_enum.value.upper()}", show_lines=True)
    table.add_column("Condition / Trigger", style="bold")
    table.add_column("Gate Action", justify="center")

    for rule, act in cfg.rules.items():
        act_style = "green" if act.value == "ALLOW" else "red" if act.value == "BLOCK" else "yellow"
        table.add_row(rule, Text(act.value, style=act_style))

    console.print(table)
    console.print(f"[dim]Policy Version: {cfg.version} | Description: {cfg.description}[/dim]")


if __name__ == "__main__":
    cli()

