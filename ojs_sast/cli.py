"""CLI interface for OJS-SAST using Click."""

import sys

import click

from ojs_sast.constants import __version__
from ojs_sast.utils.logger import logger, setup_logger

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


# Severity display colors
SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "cyan",
    "LOW": "blue",
    "INFO": "white",
}


@click.group()
@click.version_option(version=__version__, prog_name="OJS-SAST")
def cli() -> None:
    """OJS-SAST: Static Application Security Testing for Open Journal Systems.

    A comprehensive security scanner for OJS installations that analyzes
    source code, configurations, and uploaded files.
    """
    pass


def check_system_dependencies() -> None:
    """Check for required system dependencies and prompt for installation."""
    try:
        import magic
    except ImportError:
        click.echo()
        click.secho("⚠ Missing System Dependency: libmagic (python-magic)", fg="red", bold=True)
        click.echo("This dependency is required for deep file type detection during upload scanning.")
        
        if click.confirm("Do you want to attempt automatic installation?"):
            import platform
            import subprocess
            system = platform.system().lower()
            success = False
            
            try:
                if system == "linux":
                    click.echo("Attempting to install libmagic1 via apt-get...")
                    subprocess.run(["sudo", "apt-get", "update"], check=True)
                    subprocess.run(["sudo", "apt-get", "install", "-y", "libmagic1"], check=True)
                    success = True
                elif system == "darwin":
                    click.echo("Attempting to install libmagic via Homebrew...")
                    subprocess.run(["brew", "install", "libmagic"], check=True)
                    success = True
                else:
                    click.echo(f"Automatic installation not supported on {system}.")
            except Exception as e:
                click.secho(f"Installation failed: {e}", fg="red")
            
            if success:
                click.secho("✔ Installation successful!", fg="green")
                click.echo()
            else:
                click.echo("Please install it manually. See README.md for instructions.")
                sys.exit(1)
        else:
            click.echo("Please install it manually to proceed. See README.md for instructions.")
            sys.exit(1)


@cli.command()
@click.argument("target_path", type=click.Path(exists=True))
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    default="INFO",
    help="Minimum severity level to report.",
)
@click.option(
    "--list-findings",
    is_flag=True,
    help="List all individual findings in the console (warning: can be long).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output.",
)
@click.option(
    "--rules", "-r",
    multiple=True,
    help="Specific rules files to use (e.g., cve_ojs.yaml).",
)
def scan(
    target_path: str,
    min_severity: str,
    list_findings: bool,
    verbose: bool,
    rules: tuple[str, ...],
) -> None:
    """Run a security scan on an OJS installation.

    TARGET_PATH is the root directory of the OJS installation to scan.

    All three report formats (JSON, HTML, SARIF) are always generated
    automatically in a timestamped folder under results/.
    """
    import logging
    if verbose:
        logger.setLevel(logging.DEBUG)
        for h in logger.handlers:
            h.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
        for h in logger.handlers:
            h.setLevel(logging.WARNING)

    check_system_dependencies()

    from ojs_sast.engine.scanner import ScanOrchestrator

    rules_files = list(rules) if rules else None

    # Print banner
    console.print()
    console.print(Panel(
        Text(f"OJS-SAST v{__version__} | Scanning: {target_path}", style="bold cyan"),
        box=box.DOUBLE,
        border_style="blue"
    ))
    console.print()

    # Run scan
    orchestrator = ScanOrchestrator(
        target_path=target_path,
        min_severity=min_severity,
        rules_files=rules_files,
    )

    # Print OJS info and any warnings cleanly
    if orchestrator.ojs_info.is_valid:
        console.print(f"[bold green]✔[/bold green] OJS installation detected (v{orchestrator.ojs_info.version or 'unknown'})")
    else:
        console.print("[bold yellow]⚠[/bold yellow] Target may not be a valid OJS installation", style="yellow")

    for warning in orchestrator.ojs_info.warnings:
        console.print(f"[bold yellow]⚠[/bold yellow] {warning}", style="yellow")
    console.print()

    # Get totals for progress bars
    totals = orchestrator.get_scan_totals()

    # Run scan with progress bar
    total_files = totals.get("source_code", 0)
    
    if total_files > 0:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            console=console,
            transient=True, # Remove progress bar when finished
        ) as progress:
            task = progress.add_task("[cyan]Scanning Source Files", total=total_files)
            
            def update_progress(n=1):
                progress.update(task, advance=n)
                
            report = orchestrator.run(
                source_code_callback=update_progress,
            )
    else:
        report = orchestrator.run()

    # Generate reports
    output_dir = orchestrator.generate_reports(report)

    # Print results
    console.print()
    
    if len(report.findings) > 0:
        table = Table(title="[bold white]SECURITY FINDINGS[/bold white]", box=box.ROUNDED, header_style="bold magenta", expand=True)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Rule ID", style="bold cyan")
        table.add_column("Finding", style="white")
        table.add_column("Location", style="dim")
        
        for finding in report.findings:
            sev = finding.severity.value
            color = SEVERITY_COLORS.get(sev, "white")
            
            table.add_row(
                Text(sev, style=f"bold {color}"),
                finding.rule_id,
                finding.name,
                f"{finding.file_path.split('/')[-1]}:{finding.line_start}"
            )
        
        console.print(table)
    else:
        console.print(Panel("[bold green]✔ No critical vulnerabilities detected![/bold green]", border_style="green"))

    if not list_findings and len(report.findings) > 0:
        console.print(f"\n[dim]Detected {len(report.findings)} findings. Use --list-findings for detailed console output or check the reports below.[/dim]")


    # Summary
    summary_text = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = report.summary.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS[sev]
            summary_text.append(f"[bold {color}]{count} {sev}[/bold {color}]")
    
    summary_line = " | ".join(summary_text) if summary_text else "[green]No vulnerabilities[/green]"
    
    console.print()
    console.print(Panel(
        f"SUMMARY: {summary_line}\n"
        f"Duration: [bold]{report.scan_duration_seconds:.1f}s[/bold] | "
        f"Files Scanned: [bold]{report.files_scanned:,}[/bold] | "
        f"Rules Active: [bold]{report.rules_loaded}[/bold]",
        title="[bold]Scan Statistics[/bold]",
        border_style="bright_black"
    ))

    console.print()
    console.print("[bold green]✔ Scan Complete![/bold green] Reports generated in:")
    console.print(f"  [dim]Directory: {output_dir}[/dim]")
    console.print("  [blue]📄 report.json[/blue]")
    console.print("  [blue]📄 report.html[/blue]")
    console.print("  [blue]📄 report.sarif[/blue]")
    console.print()
    console.print()


@cli.group()
def rules() -> None:
    """Manage and inspect scanning rules."""
    pass


@rules.command("list")
@click.option(
    "--severity", "-s",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Filter by minimum severity.",
)
def rules_list(severity: str | None) -> None:
    """List all available scanning rules."""
    from ojs_sast.rules.loader import RuleLoader

    loader = RuleLoader()
    loader.load_all_builtin_rules()

    rules_to_show = loader.rules

    if severity:
        rules_to_show = [r for r in loader.rules if r.severity == severity.upper()]

    if not rules_to_show:
        console.print("[yellow]No rules found matching the criteria.[/yellow]")
        return

    table = Table(title="[bold white]Scanning Rules[/bold white]", box=box.SIMPLE)
    table.add_column("ID", style="bold cyan")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Name")

    for rule in sorted(rules_to_show, key=lambda r: r.id):
        sev_color = SEVERITY_COLORS.get(rule.severity, "white")
        table.add_row(
            rule.id,
            Text(rule.severity, style=f"bold {sev_color}"),
            rule.category,
            rule.name
        )

    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {len(rules_to_show)} rules")


@rules.command("show")
@click.argument("rule_id")
def rules_show(rule_id: str) -> None:
    """Show details for a specific rule."""
    from ojs_sast.rules.loader import RuleLoader

    loader = RuleLoader()
    loader.load_all_builtin_rules()

    rule = loader.get_rule(rule_id)
    if not rule:
        console.print(f"[bold red]✘ Rule '{rule_id}' not found.[/bold red]")
        sys.exit(1)

    sev_color = SEVERITY_COLORS.get(rule.severity, "white")
    
    details = Table.grid(padding=(0, 2))
    details.add_row("[bold]Name:[/bold]", rule.name)
    details.add_row("[bold]Severity:[/bold]", Text(rule.severity, style=f"bold {sev_color}"))
    details.add_row("[bold]Category:[/bold]", rule.category)
    details.add_row("[bold]Subcategory:[/bold]", rule.subcategory)
    if rule.cwe: details.add_row("[bold]CWE:[/bold]", rule.cwe)
    if rule.owasp: details.add_row("[bold]OWASP:[/bold]", rule.owasp)
    if rule.cve_references: details.add_row("[bold]CVEs:[/bold]", ", ".join(rule.cve_references))
    details.add_row("[bold]Versions:[/bold]", rule.ojs_versions_affected)

    console.print(Panel(
        details,
        title=f"[bold cyan]Rule: {rule.id}[/bold cyan]",
        border_style="blue",
        expand=False
    ))
    
    console.print("\n[bold]Description:[/bold]")
    console.print(f"  {rule.description}")
    
    if rule.remediation:
        console.print("\n[bold green]Remediation:[/bold green]")
        console.print(f"  {rule.remediation}")
    console.print()


@cli.command()
@click.argument("target_path", type=click.Path(exists=True))
def detect(target_path: str) -> None:
    """Verify an OJS installation and detect its version."""
    from ojs_sast.utils.ojs_detector import detect_ojs

    console.print(Panel(f"[bold cyan]OJS-SAST v{__version__} | Detecting: {target_path}[/bold cyan]"))

    info = detect_ojs(target_path)

    if info.is_valid:
        console.print("[bold green]✔ Valid OJS installation detected[/bold green]")
    else:
        console.print("[bold red]✘ Not a valid OJS installation[/bold red]")

    details = Table.grid(padding=(0, 2))
    details.add_row("[bold]Path:[/bold]", info.base_path)
    details.add_row("[bold]Version:[/bold]", info.version or "Unknown")
    details.add_row("[bold]Config:[/bold]", info.config_path or "Not found")
    details.add_row("[bold]Public:[/bold]", info.public_dir or "Not found")
    details.add_row("[bold]Lib:[/bold]", info.lib_dir or "Not found")
    details.add_row("[bold]Plugins:[/bold]", info.plugins_dir or "Not found")

    console.print(details)

    if info.known_vulnerabilities:
        console.print("\n[bold yellow]⚠ Known Vulnerabilities:[/bold yellow]")
        for vuln in info.known_vulnerabilities:
            console.print(f"  [yellow]• {vuln}[/yellow]")

    for warning in info.warnings:
        console.print(f"  [yellow]⚠ {warning}[/yellow]")

    console.print()


if __name__ == "__main__":
    cli()
