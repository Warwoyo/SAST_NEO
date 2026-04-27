"""Source code scanner for OJS-SAST.

Scans PHP, JS, and Smarty template files using taint analysis
and YAML rule-based pattern matching.
"""

import os
import re
import fnmatch
import uuid

from ojs_sast.categories.source_code.php_parser import parse_php_file
from ojs_sast.categories.source_code.smarty_parser import scan_smarty_template
from ojs_sast.engine.ast_matcher import ASTMatcher
from ojs_sast.engine.ast_walker import get_node_text
from ojs_sast.models.finding import Category, Finding, Severity
from ojs_sast.models.rule import Rule
from ojs_sast.utils.file_utils import find_files, get_code_snippet, read_file_safe
from ojs_sast.utils.logger import logger
from ojs_sast.utils.version_parser import is_version_vulnerable

# File extensions to scan
PHP_EXTENSIONS = {".php", ".phtml", ".inc", ".php3", ".php4", ".php5"}
JS_EXTENSIONS = {".js", ".jsx"}
TEMPLATE_EXTENSIONS = {".tpl", ".smarty"}
ALL_EXTENSIONS = PHP_EXTENSIONS | JS_EXTENSIONS | TEMPLATE_EXTENSIONS

# Directories to exclude
EXCLUDE_DIRS = {"cache", "lib/vendor", "node_modules", ".git", "__pycache__", ".svn", "tests", "tools", "lib/pkp/tests", "lib/pkp/tools"}


class SourceCodeScanner:
    """Scans source code files for security vulnerabilities."""

    def __init__(self, rules: list[Rule], target_path: str, ojs_version: str | None = None) -> None:
        self.rules = [r for r in rules if r.category == "source_code"]
        self.target_path = os.path.abspath(target_path)
        self.ojs_version = ojs_version
        self.findings: list[Finding] = []
        self.files_scanned = 0
        self._finding_counter = 0

    def scan(self, progress_callback=None) -> list[Finding]:
        """Run the full source code scan.

        Args:
            progress_callback: Optional function(increment_value) to report progress.

        Returns:
            List of all findings.
        """
        self.findings = []
        self.files_scanned = 0

        # Collect all files
        files = list(find_files(self.target_path, ALL_EXTENSIONS, EXCLUDE_DIRS))
        total = len(files)

        for filepath in files:
            _, ext = os.path.splitext(filepath)
            ext = ext.lower()

            if ext in PHP_EXTENSIONS:
                self._scan_php_file(filepath)
            elif ext in JS_EXTENSIONS:
                self._scan_with_patterns(filepath)
            elif ext in TEMPLATE_EXTENSIONS:
                self._scan_smarty_file(filepath)
                self._scan_with_patterns(filepath)

            self.files_scanned += 1
            if progress_callback:
                progress_callback(1)

        return self.findings

    def _scan_php_file(self, filepath: str) -> None:
        """Scan a single PHP file with AST structure analysis and pattern matching."""
        tree, source_bytes = parse_php_file(filepath)
        
        if tree is not None:
            self._scan_php_ast(filepath, tree, source_bytes)

        # Run regex pattern matching from rules
        self._scan_with_patterns(filepath)

    def _scan_php_ast(self, filepath: str, tree: "tree_sitter.Tree", source_bytes: bytes) -> None:
        """Run AST queries for Code Structure Analysis."""
        for rule in self.rules:
            if not self._should_run_rule(rule, filepath):
                continue
                
            if not rule.pattern_match or not rule.pattern_match.patterns:
                continue
                
            for pattern_obj in rule.pattern_match.patterns:
                if isinstance(pattern_obj, dict):
                    pattern_type = pattern_obj.get("type", rule.pattern_match.type)
                    query_string = pattern_obj.get("query", pattern_obj.get("pattern", ""))
                else:
                    pattern_type = rule.pattern_match.type
                    query_string = pattern_obj

                if pattern_type != "ast_pattern" or not query_string:
                    continue

                try:
                    matcher = ASTMatcher(query_string)
                    matches = matcher.match(tree)
                    
                    for captures in matches:
                        # By convention, if a capture named 'target' exists, we use it as the anchor.
                        # Otherwise we just use the first captured node.
                        target_nodes = captures.get("target")
                        if not target_nodes and captures:
                            target_nodes = list(captures.values())[0]
                            
                        if not target_nodes:
                            continue
                            
                        # A capture could have multiple nodes, but we usually just take the first
                        node = target_nodes[0]
                        line_num = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        matched_text = get_node_text(node, source_bytes)
                        
                        snippet = get_code_snippet(filepath, line_num, context=2)
                        self._finding_counter += 1

                        finding = Finding(
                            id=f"AST-{self._finding_counter:04d}",
                            rule_id=rule.id,
                            name=rule.name,
                            description=rule.description,
                            severity=Severity.from_string(rule.severity),
                            category=Category.SOURCE_CODE,
                            subcategory=rule.subcategory,
                            file_path=filepath,
                            line_start=line_num,
                            line_end=end_line,
                            code_snippet=snippet,
                            cwe=rule.cwe,
                            owasp=rule.owasp,
                            cve_references=rule.cve_references,
                            remediation=rule.remediation,
                            false_positive_likelihood="LOW",  # AST matches are usually high confidence
                            references=rule.references,
                            metadata={"matched_text": matched_text[:200]},
                        )
                        self.findings.append(finding)
                except Exception as e:
                    if str(e) not in getattr(self, "_logged_errors", set()):
                        logger.debug(f"Error executing AST rule {rule.id}: {e}")
                        if not hasattr(self, "_logged_errors"):
                            self._logged_errors = set()
                        self._logged_errors.add(str(e))

    def _scan_smarty_file(self, filepath: str) -> None:
        """Scan a Smarty template file for XSS patterns."""
        content = read_file_safe(filepath)
        if not content:
            return

        smarty_findings = scan_smarty_template(content)
        for sf in smarty_findings:
            self._finding_counter += 1
            snippet = get_code_snippet(filepath, sf.line_number, context=2)

            finding = Finding(
                id=f"SMARTY-{self._finding_counter:04d}",
                rule_id=f"OJS-SC-SMARTY-{sf.pattern_name.upper()}",
                name=f"Smarty Template XSS: {sf.pattern_name}",
                description=sf.description,
                severity=Severity.MEDIUM,
                category=Category.SOURCE_CODE,
                subcategory="injection",
                file_path=filepath,
                line_start=sf.line_number,
                line_end=sf.line_number,
                code_snippet=snippet,
                cwe=sf.cwe,
                owasp="A03:2021",
                remediation="Add |escape or |strip_unsafe_html modifier to the Smarty variable.",
                metadata={"matched_text": sf.matched_text[:200]},
            )
            self.findings.append(finding)

    def _scan_with_patterns(self, filepath: str) -> None:
        """Run regex pattern matching from YAML rules against a file."""
        content = read_file_safe(filepath)
        if not content:
            return

        for rule in self.rules:
            if not self._should_run_rule(rule, filepath):
                continue

            if not rule.pattern_match or not rule.pattern_match.patterns:
                continue

            # Negative matching: if require_absence is set, check if the
            # absence pattern exists in the file. If it does, the fix is
            # already applied — skip this rule for this file entirely.
            if rule.pattern_match.require_absence:
                if rule.pattern_match.require_absence in content:
                    continue

            for pattern_obj in rule.pattern_match.patterns:
                if isinstance(pattern_obj, dict):
                    pattern_type = pattern_obj.get("type", rule.pattern_match.type)
                    pattern = pattern_obj.get("query", pattern_obj.get("pattern", ""))
                else:
                    pattern_type = rule.pattern_match.type
                    pattern = pattern_obj

                if pattern_type != "regex" or not pattern:
                    continue

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

    def _should_run_rule(self, rule: Rule, filepath: str) -> bool:
        """Check if a rule should be run against a specific file based on path filters and version."""
        # Version-awareness: skip CVE rules that don't affect the target version
        if rule.ojs_versions_affected and rule.ojs_versions_affected != "all":
            if self.ojs_version and not is_version_vulnerable(rule.ojs_versions_affected, self.ojs_version):
                return False

        # Relative path for matching
        rel_path = os.path.relpath(filepath, self.target_path)

        # 1. Check exclude_paths (Blacklist takes precedence)
        if rule.exclude_paths:
            for pattern in rule.exclude_paths:
                if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(filepath, pattern):
                    return False

        # 2. Check include_paths (Whitelist)
        if rule.include_paths:
            included = False
            for pattern in rule.include_paths:
                if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(filepath, pattern):
                    included = True
                    break
            if not included:
                return False

        return True
