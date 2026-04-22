"""Source code scanner for OJS-SAST.

Scans PHP, JS, and Smarty template files using taint analysis
and YAML rule-based pattern matching.
"""

import os
import re
import uuid

from ojs_sast.categories.source_code.php_parser import parse_php_file
from ojs_sast.engine.taint.analyzer import TaintAnalyzer
from ojs_sast.models.finding import Category, Finding, Severity, TaintPath
from ojs_sast.models.rule import Rule
from ojs_sast.utils.file_utils import find_files, get_code_snippet, read_file_safe
from ojs_sast.utils.logger import logger

# File extensions to scan
PHP_EXTENSIONS = {".php", ".phtml", ".inc", ".php3", ".php4", ".php5"}
JS_EXTENSIONS = {".js", ".jsx"}
TEMPLATE_EXTENSIONS = {".tpl", ".smarty"}
ALL_EXTENSIONS = PHP_EXTENSIONS | JS_EXTENSIONS | TEMPLATE_EXTENSIONS

# Directories to exclude
EXCLUDE_DIRS = {"cache", "lib/vendor", "node_modules", ".git", "__pycache__", ".svn"}


class SourceCodeScanner:
    """Scans source code files for security vulnerabilities."""

    def __init__(self, rules: list[Rule], target_path: str) -> None:
        self.rules = [r for r in rules if r.category == "source_code"]
        self.target_path = os.path.abspath(target_path)
        self.findings: list[Finding] = []
        self.files_scanned = 0
        self._finding_counter = 0

    def scan(self) -> list[Finding]:
        """Run the full source code scan.

        Returns:
            List of all findings.
        """
        self.findings = []
        self.files_scanned = 0

        logger.info(f"Scanning source code in: {self.target_path}")

        # Collect all files
        files = list(find_files(self.target_path, ALL_EXTENSIONS, EXCLUDE_DIRS))
        total = len(files)
        logger.info(f"Found {total} source files to scan")

        for i, filepath in enumerate(files, 1):
            _, ext = os.path.splitext(filepath)
            ext = ext.lower()

            if ext in PHP_EXTENSIONS:
                self._scan_php_file(filepath)
            elif ext in JS_EXTENSIONS:
                self._scan_with_patterns(filepath)
            elif ext in TEMPLATE_EXTENSIONS:
                self._scan_with_patterns(filepath)

            self.files_scanned += 1

            if i % 100 == 0:
                logger.info(f"  Progress: {i}/{total} files scanned")

        logger.info(
            f"Source code scan complete: {self.files_scanned} files, "
            f"{len(self.findings)} findings"
        )
        return self.findings

    def _scan_php_file(self, filepath: str) -> None:
        """Scan a single PHP file with taint analysis and pattern matching."""
        tree, source_bytes = parse_php_file(filepath)

        # Run taint analysis if AST is available
        if tree is not None:
            try:
                analyzer = TaintAnalyzer(filepath, tree, source_bytes)
                taint_findings = analyzer.analyze()
                self.findings.extend(taint_findings)
            except Exception as e:
                logger.warning(f"Taint analysis failed for {filepath}: {e}")

        # Run regex pattern matching from rules
        self._scan_with_patterns(filepath)

    def _scan_with_patterns(self, filepath: str) -> None:
        """Run regex pattern matching from YAML rules against a file."""
        content = read_file_safe(filepath)
        if not content:
            return

        for rule in self.rules:
            if not rule.pattern_match or not rule.pattern_match.patterns:
                continue

            for pattern in rule.pattern_match.patterns:
                try:
                    for match in re.finditer(pattern, content, re.MULTILINE):
                        # Calculate line number
                        line_num = content[:match.start()].count("\n") + 1
                        matched_text = match.group(0)

                        # Skip if this is likely a false positive (in comments)
                        line_text = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""
                        stripped = line_text.lstrip()
                        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("#"):
                            continue

                        snippet = get_code_snippet(filepath, line_num, context=2)
                        self._finding_counter += 1

                        finding = Finding(
                            id=f"PATTERN-{self._finding_counter:04d}",
                            rule_id=rule.id,
                            name=rule.name,
                            description=rule.description,
                            severity=Severity.from_string(rule.severity),
                            category=Category.SOURCE_CODE,
                            subcategory=rule.subcategory,
                            file_path=filepath,
                            line_start=line_num,
                            line_end=line_num,
                            code_snippet=snippet,
                            cwe=rule.cwe,
                            owasp=rule.owasp,
                            cve_references=rule.cve_references,
                            remediation=rule.remediation,
                            references=rule.references,
                            metadata={"matched_pattern": matched_text[:200]},
                        )
                        self.findings.append(finding)

                except re.error as e:
                    logger.warning(f"Invalid regex in rule {rule.id}: {e}")
