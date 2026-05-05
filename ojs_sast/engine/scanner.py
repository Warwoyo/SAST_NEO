"""Main scan orchestrator for OJS-SAST.

Coordinates all category scanners, collects findings, and generates reports.
"""

import os
import time
import uuid
from datetime import datetime

from ojs_sast.constants import __version__
from ojs_sast.categories.config.scanner import ConfigScanner
from ojs_sast.categories.source_code.scanner import SourceCodeScanner
from ojs_sast.categories.uploaded_file.scanner import UploadedFileScanner
from ojs_sast.models.finding import Finding, Severity
from ojs_sast.models.report import ScanReport
from ojs_sast.reporters.html_reporter import generate_html_report
from ojs_sast.reporters.json_reporter import generate_json_report
from ojs_sast.reporters.sarif_reporter import generate_sarif_report
from ojs_sast.rules.loader import RuleLoader
from ojs_sast.utils.logger import logger
from ojs_sast.utils.ojs_detector import OJSInstallation, detect_ojs


class ScanOrchestrator:
    """Main orchestrator that runs all scanners and generates reports."""

    def __init__(
        self,
        target_path: str,
        categories: list[str] | None = None,
        nginx_config: str | None = None,
        apache_config: str | None = None,
        min_severity: str = "INFO",
        upload_dirs: list[str] | None = None,
        rules_files: list[str] | None = None,
        enable_taint: bool = False,
    ) -> None:
        self.target_path = os.path.abspath(target_path)
        self.categories = categories or ["source_code", "config", "uploaded_file"]
        self.nginx_config = nginx_config
        self.apache_config = apache_config
        self.min_severity = min_severity
        self.upload_dirs = upload_dirs or []
        self.rules_files = rules_files or []
        self.enable_taint = enable_taint
        self.findings: list[Finding] = []
        self.files_scanned = 0
        self.ojs_info: OJSInstallation = detect_ojs(self.target_path)



    def generate_reports(self, report: ScanReport) -> str:
        """Generate all report formats and return the output directory.

        Args:
            report: The completed scan report.

        Returns:
            Absolute path to the timestamped output directory.
        """
        # Create timestamped output directory
        ts_folder = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_results = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "results",
        )
        output_dir = os.path.join(base_results, ts_folder)
        os.makedirs(output_dir, exist_ok=True)

        # Generate all three formats
        json_path = generate_json_report(report, output_dir)
        html_path = generate_html_report(report, output_dir)
        sarif_path = generate_sarif_report(report, output_dir)

        logger.info("=" * 50)
        logger.info("✔ Scan Complete! Reports generated:")
        logger.info(f"  📄 {json_path}")
        logger.info(f"  📄 {html_path}")
        logger.info(f"  📄 {sarif_path}")

        return output_dir

    def _resolve_upload_dirs(self) -> list[str]:
        """Resolve upload directories from OJS config or CLI args.

        Validates that resolved paths are actual upload directories,
        not the OJS source root or parent directories (which would cause
        false positives by scanning application source code).
        """
        dirs: list[str] = []
        ojs_root = os.path.normpath(self.target_path)

        def _is_safe_upload_dir(path: str) -> bool:
            """Check that a path is a valid upload dir, not the OJS root or above."""
            norm = os.path.normpath(os.path.abspath(path))
            if not os.path.isdir(norm):
                logger.debug(f"Upload dir does not exist, skipping: {norm}")
                return False
            # Reject if it IS the OJS root (would scan entire source tree)
            if norm == ojs_root:
                logger.warning(
                    f"Upload dir '{norm}' is the OJS root — skipping to avoid "
                    "scanning source code as uploaded files"
                )
                return False
            # Reject if OJS root is INSIDE this path (parent of root)
            if ojs_root.startswith(norm + os.sep):
                logger.warning(
                    f"Upload dir '{norm}' is a parent of the OJS root — skipping"
                )
                return False
            return True

        # 1. CLI-specified upload directories (user override — trust but validate)
        for d in self.upload_dirs:
            absd = os.path.normpath(os.path.abspath(d))
            if _is_safe_upload_dir(absd):
                dirs.append(absd)

        # 2. Config-extracted directories (from config.inc.php)
        if self.ojs_info:
            if self.ojs_info.files_dir and _is_safe_upload_dir(self.ojs_info.files_dir):
                norm = os.path.normpath(os.path.abspath(self.ojs_info.files_dir))
                if norm not in dirs:
                    dirs.append(norm)
                    logger.info(f"Upload scan: files_dir → {norm}")

            if self.ojs_info.public_files_dir and _is_safe_upload_dir(self.ojs_info.public_files_dir):
                norm = os.path.normpath(os.path.abspath(self.ojs_info.public_files_dir))
                if norm not in dirs:
                    dirs.append(norm)
                    logger.info(f"Upload scan: public_files_dir → {norm}")

        if not dirs:
            logger.warning(
                "No valid upload directories resolved. "
                "Ensure files_dir / public_files_dir are set in config.inc.php "
                "or pass --upload-dir explicitly."
            )

        return dirs

    def get_scan_totals(self) -> dict[str, int]:
        """Pre-calculate the total number of files to scan for progress bars.

        Returns:
            Dictionary with category names and their file counts.
        """
        from ojs_sast.categories.source_code.scanner import ALL_EXTENSIONS, EXCLUDE_DIRS
        from ojs_sast.utils.file_utils import count_files

        totals = {}

        if "source_code" in self.categories:
            totals["source_code"] = count_files(
                self.target_path, ALL_EXTENSIONS, EXCLUDE_DIRS
            )

        if "uploaded_file" in self.categories:
            from ojs_sast.categories.uploaded_file.scanner import UploadedFileScanner
            upload_dirs = self._resolve_upload_dirs()
            total_uploads = 0
            for d in upload_dirs:
                total_uploads += count_files(
                    d, extensions=None,
                    exclude_dirs=UploadedFileScanner._OJS_SOURCE_DIRS,
                )
            totals["uploaded_file"] = total_uploads

        return totals

    def run(
        self,
        source_code_callback=None,
        upload_callback=None
    ) -> ScanReport:
        """Execute the full scan pipeline.

        Args:
            source_code_callback: Callback for source code scanning progress.
            upload_callback: Callback for upload scanning progress.

        Returns:
            ScanReport with all findings and metadata.
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        logger.info(f"OJS-SAST v{__version__} | Scanning: {self.target_path}")
        logger.info("=" * 50)

        # Step 2: Load rules
        rule_loader = RuleLoader()
        rules_loaded = 0
        is_cve_ojs = False
        
        if self.rules_files:
            for rfile in self.rules_files:
                if "cve_ojs" in rfile.lower():
                    is_cve_ojs = True
                
                # Try to load rule if it exists as an absolute or relative path
                if os.path.exists(rfile):
                    rules_loaded += rule_loader.load_file(rfile)
                else:
                    # Look for it in the built-in rules directory
                    base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "categories")
                    found = False
                    for root, _, files in os.walk(base_dir):
                        for f in files:
                            if f == rfile or f == rfile + ".yaml" or f == rfile + ".yml":
                                rules_loaded += rule_loader.load_file(os.path.join(root, f))
                                found = True
                    if not found:
                        logger.warning(f"Could not find rules file: {rfile}")
        else:
            rules_loaded = rule_loader.load_all_builtin_rules()

        # Step 3: Run category scanners
        if "source_code" in self.categories:
            disable_taint = is_cve_ojs and not self.enable_taint
            ojs_version = self.ojs_info.version if self.ojs_info else None
            sc_scanner = SourceCodeScanner(
                rule_loader.rules, self.target_path,
                disable_taint=disable_taint,
                ojs_version=ojs_version,
            )
            sc_findings = sc_scanner.scan(progress_callback=source_code_callback)
            self.findings.extend(sc_findings)
            self.files_scanned += sc_scanner.files_scanned

        if "config" in self.categories:
            cfg_scanner = ConfigScanner(
                rule_loader.rules,
                self.target_path,
                nginx_config=self.nginx_config,
                apache_config=self.apache_config,
                ojs_config_path=self.ojs_info.config_path if self.ojs_info else None,
            )
            cfg_findings = cfg_scanner.scan()
            self.findings.extend(cfg_findings)

        if "uploaded_file" in self.categories:
            upload_dirs = self._resolve_upload_dirs()
            if upload_dirs:
                uf_scanner = UploadedFileScanner(rule_loader.rules, upload_dirs)
                uf_findings = uf_scanner.scan(progress_callback=upload_callback)
                self.findings.extend(uf_findings)
                self.files_scanned += uf_scanner.files_scanned

        # Step 4: Deduplicate and Filter by severity
        self.findings = self._deduplicate_findings(self.findings)
        if self.min_severity != "INFO":
            self.findings = self._filter_by_severity(self.findings, self.min_severity)

        # Step 5: Build report
        duration = time.time() - start_time
        summary = ScanReport.compute_summary(self.findings)

        report = ScanReport(
            scan_id=scan_id,
            timestamp=timestamp,
            ojs_version=self.ojs_info.version if self.ojs_info else None,
            ojs_path=self.target_path,
            scan_duration_seconds=round(duration, 2),
            findings=self.findings,
            summary=summary,
            scanner_version=__version__,
            categories_scanned=self.categories,
            files_scanned=self.files_scanned,
            rules_loaded=rules_loaded,
        )

        return report

    @staticmethod
    def _filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
        """Filter findings by minimum severity level."""
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_level = severity_order.get(min_severity.upper(), 0)
        return [
            f for f in findings
            if severity_order.get(f.severity.value, 0) >= min_level
        ]

    @staticmethod
    def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on file, line, rule, and category."""
        seen = set()
        unique_findings = []
        for finding in findings:
            # Create a unique signature for the finding
            signature = (
                finding.file_path,
                finding.line_start,
                finding.rule_id,
                finding.category.value,
            )
            if signature not in seen:
                seen.add(signature)
                unique_findings.append(finding)
        return unique_findings
