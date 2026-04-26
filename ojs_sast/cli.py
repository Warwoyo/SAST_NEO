"""CLI interface for OJS-SAST using Click."""

import sys

import click

from ojs_sast.constants import __version__
from ojs_sast.utils.logger import logger, setup_logger


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
    "--category", "-c",
    multiple=True,
    type=click.Choice(["source_code", "config", "uploaded_file"]),
    help="Scan specific category (can be repeated). Default: all.",
)
@click.option(
    "--nginx-config",
    type=click.Path(exists=True),
    help="Path to Nginx configuration file.",
)
@click.option(
    "--apache-config",
    type=click.Path(exists=True),
    help="Path to Apache configuration file.",
)
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
    "--upload-dir",
    multiple=True,
    type=click.Path(exists=True),
    help="Additional upload directory to scan (can be repeated).",
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
@click.option(
    "--enable-taint",
    is_flag=True,
    help="Explicitly enable taint analysis even when using specific rules.",
)
def scan(
    target_path: str,
    category: tuple[str, ...],
    nginx_config: str | None,
    apache_config: str | None,
    min_severity: str,
    list_findings: bool,
    upload_dir: tuple[str, ...],
    verbose: bool,
    rules: tuple[str, ...],
    enable_taint: bool,
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

    categories = list(category) if category else None
    upload_dirs = list(upload_dir) if upload_dir else None
    rules_files = list(rules) if rules else None

    # Print banner
    click.echo()
    click.secho(f"OJS-SAST v{__version__} | Scanning: {target_path}", fg="bright_blue", bold=True)
    click.secho("━" * 50, fg="bright_black")
    click.echo()

    # Run scan
    orchestrator = ScanOrchestrator(
        target_path=target_path,
        categories=categories,
        nginx_config=nginx_config,
        apache_config=apache_config,
        min_severity=min_severity,
        upload_dirs=upload_dirs,
        rules_files=rules_files,
        enable_taint=enable_taint,
    )

    # Print OJS info and any warnings cleanly before starting progress bars
    if orchestrator.ojs_info.is_valid:
        click.secho(f"✔ OJS installation detected (v{orchestrator.ojs_info.version or 'unknown'})", fg="green")
    else:
        click.secho("⚠ Target may not be a valid OJS installation", fg="yellow")

    for warning in orchestrator.ojs_info.warnings:
        click.secho(f"⚠ {warning}", fg="yellow")
    click.echo()

    # Get totals for progress bars
    totals = orchestrator.get_scan_totals()

    # Run scan with progress bars
    class ProgressBarManager:
        def __init__(self, totals):
            self.totals = totals
            self.sc_bar = None
            self.sc_closed = False
            self.uf_bar = None
            self.uf_closed = False

        def update_sc(self, n=1):
            if self.sc_bar is None:
                self.sc_bar = click.progressbar(
                    length=self.totals.get("source_code", 0),
                    label="[source_code] Scanning PHP files",
                    show_pos=True,
                    file=sys.stderr,
                    fill_char="█",
                    empty_char="░",
                )
                self.sc_bar.__enter__()
            
            if not self.sc_closed:
                self.sc_bar.update(n)
                if self.sc_bar.pos >= self.sc_bar.length:
                    self.sc_bar.__exit__(None, None, None)
                    self.sc_closed = True
                    click.echo()

        def update_uf(self, n=1):
            if self.uf_bar is None:
                self.uf_bar = click.progressbar(
                    length=self.totals.get("uploaded_file", 0),
                    label="[uploaded]    Scanning uploads  ",
                    show_pos=True,
                    file=sys.stderr,
                    fill_char="█",
                    empty_char="░",
                )
                self.uf_bar.__enter__()
            
            if not self.uf_closed:
                self.uf_bar.update(n)
                if self.uf_bar.pos >= self.uf_bar.length:
                    self.uf_bar.__exit__(None, None, None)
                    self.uf_closed = True
                    click.echo()

    pb_manager = ProgressBarManager(totals)

    report = orchestrator.run(
        source_code_callback=pb_manager.update_sc,
        upload_callback=pb_manager.update_uf
    )

    if pb_manager.sc_bar and not pb_manager.sc_closed:
        pb_manager.sc_bar.__exit__(None, None, None)
        click.echo()
    if pb_manager.uf_bar and not pb_manager.uf_closed:
        pb_manager.uf_bar.__exit__(None, None, None)
        click.echo()

    # Generate reports
    output_dir = orchestrator.generate_reports(report)

    # Print results
    click.echo()
    click.secho("━" * 50, fg="bright_black")
    click.secho("SCAN RESULTS", fg="bright_white", bold=True)
    click.secho("━" * 50, fg="bright_black")
    click.echo()

    if list_findings:
        for finding in report.findings:
            sev = finding.severity.value
            color = SEVERITY_COLORS.get(sev, "white")

            click.secho(f"[{sev:8s}] ", fg=color, nl=False, bold=True)
            click.secho(f"{finding.rule_id} — {finding.name}", fg="bright_white")

            # File location
            click.echo(f"  File: {finding.file_path}", nl=False)
            if finding.line_start > 0:
                click.echo(f":{finding.line_start}")
            else:
                click.echo()

            # Taint path
            if finding.taint_path:
                click.secho(
                    f"  Taint: {finding.taint_path.to_display_string()}",
                    fg="bright_black",
                )

            # CWE/OWASP
            meta_parts = []
            if finding.cwe:
                meta_parts.append(finding.cwe)
            if finding.owasp:
                meta_parts.append(f"OWASP: {finding.owasp}")
            if meta_parts:
                click.echo(f"  {' | '.join(meta_parts)}")

            # Remediation
            if finding.remediation:
                fix_preview = finding.remediation[:120]
                if len(finding.remediation) > 120:
                    fix_preview += "..."
                click.secho(f"  Fix:  {fix_preview}", fg="green")

            click.echo()
    else:
        click.echo(f"Total findings detected: {len(report.findings)}")
        click.echo("Detailed results have been saved to the report files.")
        click.echo("Use --list-findings to see them here.")
        click.echo()

    # Summary
    click.secho("━" * 50, fg="bright_black")
    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = report.summary.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS[sev]
            summary_parts.append(click.style(f"{count} {sev}", fg=color, bold=True))
    click.echo("SUMMARY: " + " | ".join(summary_parts))

    click.echo(
        f"Duration: {report.scan_duration_seconds:.1f}s | "
        f"Files: {report.files_scanned:,} | "
        f"Rules: {report.rules_loaded}"
    )
    click.secho("━" * 50, fg="bright_black")

    click.echo()
    click.secho("✔ Scan Complete! Reports have been automatically generated.", fg="green", bold=True)
    click.secho(f"✔ Output Directory: {output_dir}/", fg="green")
    click.echo("    📄 report.json")
    click.echo("    📄 report.html")
    click.echo("    📄 report.sarif")
    click.echo()


@cli.group()
def rules() -> None:
    """Manage and inspect scanning rules."""
    pass


@rules.command("list")
@click.option(
    "--category", "-c",
    type=click.Choice(["source_code", "config", "uploaded_file"]),
    help="Filter by category.",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Filter by minimum severity.",
)
def rules_list(category: str | None, severity: str | None) -> None:
    """List all available scanning rules."""
    from ojs_sast.rules.loader import RuleLoader

    loader = RuleLoader()
    loader.load_all_builtin_rules()

    rules_to_show = loader.rules

    if category:
        rules_to_show = [r for r in rules_to_show if r.category == category]
    if severity:
        rules_to_show = loader.get_rules_by_severity(severity)
        if category:
            rules_to_show = [r for r in rules_to_show if r.category == category]

    if not rules_to_show:
        click.echo("No rules found matching the criteria.")
        return

    click.echo()
    click.secho(f"{'ID':<25} {'SEVERITY':<10} {'CATEGORY':<15} {'NAME'}", fg="bright_white", bold=True)
    click.secho("─" * 90, fg="bright_black")

    for rule in sorted(rules_to_show, key=lambda r: r.id):
        sev_color = SEVERITY_COLORS.get(rule.severity, "white")
        click.echo(
            f"{rule.id:<25} "
            f"{click.style(rule.severity, fg=sev_color):<21} "
            f"{rule.category:<15} "
            f"{rule.name}"
        )

    click.echo()
    click.echo(f"Total: {len(rules_to_show)} rules")


@rules.command("show")
@click.argument("rule_id")
def rules_show(rule_id: str) -> None:
    """Show details for a specific rule."""
    from ojs_sast.rules.loader import RuleLoader

    loader = RuleLoader()
    loader.load_all_builtin_rules()

    rule = loader.get_rule(rule_id)
    if not rule:
        click.secho(f"Rule '{rule_id}' not found.", fg="red")
        sys.exit(1)

    click.echo()
    sev_color = SEVERITY_COLORS.get(rule.severity, "white")
    click.secho(f"Rule: {rule.id}", fg="bright_blue", bold=True)
    click.secho("─" * 50, fg="bright_black")
    click.echo(f"Name:        {rule.name}")
    click.echo(f"Severity:    {click.style(rule.severity, fg=sev_color, bold=True)}")
    click.echo(f"Category:    {rule.category}")
    click.echo(f"Subcategory: {rule.subcategory}")
    if rule.cwe:
        click.echo(f"CWE:         {rule.cwe}")
    if rule.owasp:
        click.echo(f"OWASP:       {rule.owasp}")
    if rule.cve_references:
        click.echo(f"CVEs:        {', '.join(rule.cve_references)}")
    click.echo(f"OJS Versions: {rule.ojs_versions_affected}")
    click.echo()
    click.secho("Description:", fg="bright_white", bold=True)
    click.echo(f"  {rule.description}")
    if rule.remediation:
        click.echo()
        click.secho("Remediation:", fg="green", bold=True)
        click.echo(f"  {rule.remediation}")
    click.echo()


@cli.command()
@click.argument("target_path", type=click.Path(exists=True))
def detect(target_path: str) -> None:
    """Verify an OJS installation and detect its version."""
    from ojs_sast.utils.ojs_detector import detect_ojs

    click.echo()
    click.secho(f"OJS-SAST v{__version__} | Detecting: {target_path}", fg="bright_blue", bold=True)
    click.secho("━" * 50, fg="bright_black")

    info = detect_ojs(target_path)

    if info.is_valid:
        click.secho("✔ Valid OJS installation detected", fg="green", bold=True)
    else:
        click.secho("✘ Not a valid OJS installation", fg="red", bold=True)

    click.echo()
    click.echo(f"  Path:      {info.base_path}")
    click.echo(f"  Version:   {info.version or 'Unknown'}")
    click.echo(f"  Config:    {info.config_path or 'Not found'}")
    click.echo(f"  Public:    {info.public_dir or 'Not found'}")
    click.echo(f"  Lib:       {info.lib_dir or 'Not found'}")
    click.echo(f"  Classes:   {info.classes_dir or 'Not found'}")
    click.echo(f"  Plugins:   {info.plugins_dir or 'Not found'}")
    click.echo(f"  Files Dir: {info.files_dir or 'Not found'}")

    if info.known_vulnerabilities:
        click.echo()
        click.secho("⚠ Known Vulnerabilities:", fg="yellow", bold=True)
        for vuln in info.known_vulnerabilities:
            click.secho(f"  • {vuln}", fg="yellow")

    for warning in info.warnings:
        click.secho(f"  ⚠ {warning}", fg="yellow")

    click.echo()


if __name__ == "__main__":
    cli()
