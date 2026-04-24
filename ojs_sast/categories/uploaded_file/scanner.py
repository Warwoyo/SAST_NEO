"""Uploaded file scanner for OJS-SAST.

Scans uploaded files for dangerous extensions, MIME mismatches,
webshell signatures, and embedded payloads.
"""

import os
import re

from ojs_sast.categories.uploaded_file.magic_detector import detect_mime_type, is_extension_mismatch
from ojs_sast.categories.uploaded_file.validator import (
    ALL_DANGEROUS,
    get_extension,
    get_risk_level,
    is_dangerous_extension,
    is_double_extension,
)
from ojs_sast.models.finding import Category, Finding, Severity
from ojs_sast.models.rule import Rule
from ojs_sast.utils.file_utils import find_files, read_file_safe
from ojs_sast.utils.logger import logger


class UploadedFileScanner:
    """Scans uploaded files in OJS directories for security threats."""

    def __init__(
        self,
        rules: list[Rule],
        upload_dirs: list[str],
    ) -> None:
        self.rules = [r for r in rules if r.category == "uploaded_file"]
        self.upload_dirs = [os.path.abspath(d) for d in upload_dirs if os.path.isdir(d)]
        self.findings: list[Finding] = []
        self.files_scanned = 0
        self._finding_counter = 0

        # Load patterns from rules
        self._dangerous_patterns: list[tuple[str, re.Pattern]] = []
        self._webshell_patterns: list[tuple[str, re.Pattern]] = []
        self._dangerous_extension_rules: list[Rule] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load regex patterns from rules."""
        for rule in self.rules:
            if rule.dangerous_extensions:
                self._dangerous_extension_rules.append(rule)
            
            if not rule.pattern_match:
                continue
            for pat_str in rule.pattern_match.patterns:
                try:
                    compiled = re.compile(pat_str, re.IGNORECASE | re.MULTILINE)
                    if "webshell" in rule.subcategory or "webshell" in rule.id.lower():
                        self._webshell_patterns.append((rule.id, compiled))
                    else:
                        self._dangerous_patterns.append((rule.id, compiled))
                except re.error:
                    logger.warning(f"Invalid pattern in rule {rule.id}: {pat_str}")

    def scan(self, progress_callback=None) -> list[Finding]:
        """Run the full uploaded file scan.
        
        Args:
            progress_callback: Optional function(increment_value) to report progress.
        """
        self.findings = []
        self.files_scanned = 0

        if not self.upload_dirs:
            logger.warning("No upload directories specified or found")
            return []

        for upload_dir in self.upload_dirs:
            self._scan_directory(upload_dir, progress_callback)

        return self.findings

    def _scan_directory(self, directory: str, progress_callback=None) -> None:
        """Scan all files in an upload directory."""
        for filepath in find_files(directory, extensions=None, exclude_dirs=set()):
            self.files_scanned += 1
            self._scan_file(filepath)
            if progress_callback:
                progress_callback(1)

    def _scan_file(self, filepath: str) -> None:
        """Scan a single uploaded file."""
        ext = get_extension(filepath)

        # 1. Check for dangerous extensions using Rules
        is_dangerous = False
        scan_for_webshell = False

        for rule in self._dangerous_extension_rules:
            for d_ext in rule.dangerous_extensions:
                if filepath.lower().endswith(d_ext.lower()):
                    is_dangerous = True
                    self._create_finding(
                        rule_id=rule.id,
                        name=rule.name,
                        description=rule.description,
                        severity=Severity.from_string(rule.severity),
                        filepath=filepath,
                        cwe=rule.cwe or "",
                        owasp=rule.owasp or "A04:2021",
                        remediation=rule.remediation,
                    )
                    # If it's a PHP-like file, mark to scan for webshell content
                    if "php" in d_ext.lower() or "phtml" in d_ext.lower() or "phar" in d_ext.lower():
                        scan_for_webshell = True
                    break # One extension match per rule is enough

        if scan_for_webshell:
            self._scan_php_content(filepath)

        # Check for double extensions
        if is_double_extension(filepath):
            self._create_finding(
                rule_id="OJS-UF-EXT-002",
                name="Double extension detected (possible bypass attempt)",
                description=f"File '{os.path.basename(filepath)}' uses double extension, "
                            "which may be an attempt to bypass upload validation.",
                severity=Severity.HIGH,
                filepath=filepath,
                cwe="CWE-434",
                remediation="Delete the file and review upload validation logic.",
            )

        # Check for MIME type mismatch
        is_mismatch, actual_mime, expected_mime = is_extension_mismatch(filepath)
        if is_mismatch and actual_mime:
            # Especially dangerous if content is PHP but extension is not
            if "php" in (actual_mime or "").lower() and ext not in ALL_DANGEROUS:
                self._create_finding(
                    rule_id="OJS-UF-MIME-001",
                    name="PHP content disguised with non-PHP extension",
                    description=f"File has extension '{ext}' but contains PHP code "
                                f"(detected as {actual_mime}).",
                    severity=Severity.CRITICAL,
                    filepath=filepath,
                    cwe="CWE-434",
                    remediation="Delete the file immediately. This is likely a webshell.",
                )
                self._scan_php_content(filepath)
            elif actual_mime != expected_mime:
                self._create_finding(
                    rule_id="OJS-UF-MIME-002",
                    name="File extension does not match content type",
                    description=f"Extension suggests '{expected_mime}' but actual type is '{actual_mime}'.",
                    severity=Severity.MEDIUM,
                    filepath=filepath,
                    cwe="CWE-434",
                    remediation="Verify the file is legitimate. Rename to correct extension or delete.",
                )

        # Scan non-PHP files for embedded payloads
        if ext in {".pdf"}:
            self._scan_pdf_payloads(filepath)

    def _scan_php_content(self, filepath: str) -> None:
        """Scan PHP file content for webshell patterns."""
        content = read_file_safe(filepath)
        if not content:
            return

        # Check webshell patterns
        for rule_id, pattern in self._webshell_patterns:
            if pattern.search(content):
                match = pattern.search(content)
                matched_text = match.group(0)[:100] if match else ""
                self._create_finding(
                    rule_id=rule_id,
                    name="Webshell signature detected",
                    description=f"Known webshell pattern found: {matched_text}",
                    severity=Severity.CRITICAL,
                    filepath=filepath,
                    cwe="CWE-506",
                    remediation="Delete the file immediately and audit server access.",
                )
                return  # One webshell finding per file is enough

        # Check dangerous code patterns
        for rule_id, pattern in self._dangerous_patterns:
            if pattern.search(content):
                match = pattern.search(content)
                matched_text = match.group(0)[:100] if match else ""
                self._create_finding(
                    rule_id=rule_id,
                    name="Dangerous code pattern in uploaded file",
                    description=f"Suspicious pattern found: {matched_text}",
                    severity=Severity.HIGH,
                    filepath=filepath,
                    cwe="CWE-94",
                    remediation="Review and likely delete the file.",
                )

    def _scan_pdf_payloads(self, filepath: str) -> None:
        """Check PDF files for embedded JavaScript or auto-open actions."""
        content = read_file_safe(filepath)
        if not content:
            return

        # Check for JavaScript in PDF
        js_patterns = [
            r"/JavaScript",
            r"/JS\s*\(",
            r"/OpenAction",
            r"/AA\s*<<",
            r"/Launch",
        ]
        for pattern in js_patterns:
            if re.search(pattern, content):
                self._create_finding(
                    rule_id="OJS-UF-PDF-001",
                    name="PDF with embedded JavaScript or auto-action",
                    description="The PDF contains embedded JavaScript or auto-open actions "
                                "that could execute malicious code.",
                    severity=Severity.MEDIUM,
                    filepath=filepath,
                    cwe="CWE-94",
                    remediation="Review the PDF content. Remove JavaScript actions if not required.",
                )
                break

    def _create_finding(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        filepath: str,
        cwe: str = "",
        owasp: str = "A04:2021",
        remediation: str = "",
    ) -> None:
        """Create a finding for an uploaded file issue."""
        self._finding_counter += 1
        finding = Finding(
            id=f"UPLOAD-{self._finding_counter:04d}",
            rule_id=rule_id,
            name=name,
            description=description,
            severity=severity,
            category=Category.UPLOADED_FILE,
            subcategory="uploaded_file",
            file_path=filepath,
            line_start=0,
            line_end=0,
            code_snippet="",
            cwe=cwe,
            owasp=owasp,
            remediation=remediation,
        )
        self.findings.append(finding)
