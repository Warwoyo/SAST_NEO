"""Core taint analysis engine for OJS-SAST.

Implements forward data-flow analysis to track tainted data from
sources through variable assignments to dangerous sinks.
"""

import re
from dataclasses import dataclass, field
from typing import Any

# Database fetch functions — output is trusted (not first-order user input).
# If a variable is assigned from one of these, its taint chain is truncated.
_DB_FETCH_FUNCTIONS = [
    "mysql_fetch_row", "mysql_fetch_assoc", "mysql_fetch_array",
    "mysql_fetch_object", "mysqli_fetch_row", "mysqli_fetch_assoc",
    "mysqli_fetch_array", "mysqli_fetch_object",
    "fetch", "fetchRow", "fetchAssoc", "fetchAll",
    "retrieve",
]
_DB_FETCH_REGEXES: list[re.Pattern] = [
    re.compile(rf"\b{re.escape(f)}\b") for f in _DB_FETCH_FUNCTIONS
]

# OOP objects that are safe when calling generic sink names like execute().
_SAFE_OBJECT_PATTERNS: list[re.Pattern] = [
    re.compile(rf"\b{re.escape(kw)}") for kw in
    ["Form", "Filter", "Plugin", "Handler", "Validator"]
]

from ojs_sast.engine.ast_walker import (
    find_nodes_by_types,
    find_variables_in_node,
    get_assignment_target,
    get_assignment_value,
    get_function_arguments,
    get_function_name,
    get_line_number,
    get_node_text,
    walk_tree,
)
from ojs_sast.engine.taint.sanitizers import get_sanitizer_category, is_effective_sanitizer, is_sanitizer
from ojs_sast.engine.taint.sinks import get_sink_categories, is_taint_sink
from ojs_sast.engine.taint.sources import get_source_category, is_taint_source
from ojs_sast.models.finding import Category, Finding, Severity, TaintPath
from ojs_sast.models.rule import Rule
from ojs_sast.utils.file_utils import get_code_snippet
from ojs_sast.utils.logger import logger


@dataclass
class TaintedVariable:
    """Tracks a tainted variable through data flow."""
    name: str
    source: str
    source_line: int
    taint_path: list[str] = field(default_factory=list)
    sanitized_by: str | None = None
    sanitizer_category: str | None = None
    custom_rule: Rule | None = None


class TaintAnalyzer:
    """Forward data-flow taint analysis engine.

    Algorithm:
    1. Parse PHP → AST via tree-sitter
    2. Walk AST to identify taint sources
    3. Mark variables receiving values from sources as tainted
    4. Follow data flow through assignments (taint propagation)
    5. If tainted var passes through sanitizer → record sanitization
    6. If tainted var reaches a sink → generate Finding with TaintPath
    """

    def __init__(self, filepath: str, tree: Any, source_bytes: bytes, finding_id_offset: int = 0, custom_rules: list[Rule] | None = None) -> None:
        self.filepath = filepath
        self.tree = tree
        self.source_bytes = source_bytes
        self.tainted_vars: dict[str, TaintedVariable] = {}
        self.findings: list[Finding] = []
        self._finding_counter = finding_id_offset
        self.custom_rules = custom_rules or []
        
        self._compiled_custom_sources: dict[re.Pattern, Rule] = {}
        self._compiled_custom_sinks: dict[re.Pattern, Rule] = {}
        self._compiled_custom_sanitizers: dict[re.Pattern, Rule] = {}

        for rule in self.custom_rules:
            if not rule.taint_analysis:
                continue
            for src in rule.taint_analysis.sources:
                pat = self._build_regex(src)
                if pat: self._compiled_custom_sources[pat] = rule
            for sink in rule.taint_analysis.sinks:
                pat = self._build_regex(sink)
                if pat: self._compiled_custom_sinks[pat] = rule
            for san in rule.taint_analysis.sanitizers:
                pat = self._build_regex(san)
                if pat: self._compiled_custom_sanitizers[pat] = rule

    @staticmethod
    def _build_regex(raw_string: str) -> re.Pattern | None:
        # Strip comments, descriptions and parameters
        clean = re.split(r'\s+[—#]|\s+\(', raw_string)[0].strip()
        if not clean:
            return None
        if clean.endswith("()"):
            clean = clean[:-2]
        
        escaped = re.escape(clean)
        if clean.startswith("$"):
            # Ensure safe word boundary if it ends with alphanumeric
            suffix = r"\b" if clean[-1].isalnum() or clean[-1] == "_" else ""
            return re.compile(rf"(?<![a-zA-Z0-9_]){escaped}{suffix}")
        else:
            return re.compile(rf"(?<!\$)(?<!->)\b{escaped}\s*\(")

    def analyze(self) -> list[Finding]:
        """Run taint analysis on the parsed PHP file.

        Returns:
            List of findings from taint analysis.
        """
        if self.tree is None:
            return []

        root = self.tree.root_node

        # Phase 1: Identify initial taint sources
        self._find_taint_sources(root)

        # Phase 2: Propagate taint through assignments
        self._propagate_taint(root)

        # Phase 3: Check sinks for tainted data
        self._check_sinks(root)

        return self.findings

    def _find_taint_sources(self, root: Any) -> None:
        """Find all taint sources and mark initial tainted variables."""
        assignment_types = {"assignment_expression", "augmented_assignment_expression"}
        assignments = find_nodes_by_types(root, assignment_types)

        for node in assignments:
            target = get_assignment_target(node, self.source_bytes)
            value_node = node.child_by_field_name("right")

            if not target or not value_node:
                continue

            value_text = get_node_text(value_node, self.source_bytes)

            is_source = False
            source_cat = "unknown"
            custom_rule = None

            if is_taint_source(value_text):
                is_source = True
                source_cat = get_source_category(value_text) or "unknown"
            else:
                for pat, rule in self._compiled_custom_sources.items():
                    if pat.search(value_text):
                        is_source = True
                        source_cat = rule.subcategory or "custom"
                        custom_rule = rule
                        break

            if is_source:
                line = get_line_number(node)

                # Check if the source is wrapped in a sanitizer
                sanitized_by = None
                sanitizer_cat = None
                if is_sanitizer(value_text):
                    sanitized_by = value_text
                    sanitizer_cat = get_sanitizer_category(value_text)
                else:
                    for pat, rule in self._compiled_custom_sanitizers.items():
                        if pat.search(value_text):
                            sanitized_by = value_text
                            sanitizer_cat = "custom_sanitizer"
                            break

                self.tainted_vars[target] = TaintedVariable(
                    name=target,
                    source=value_text,
                    source_line=line,
                    taint_path=[f"{target} = {value_text} (line {line})"
                                + (f" [SANITIZED by {sanitizer_cat}]" if sanitized_by else "")],
                    sanitized_by=sanitized_by,
                    sanitizer_category=sanitizer_cat,
                    custom_rule=custom_rule,
                )
                logger.debug(
                    f"Taint source found: {target} = {value_text} "
                    f"[{source_cat}] at {self.filepath}:{line}"
                    + (f" (sanitized by {sanitizer_cat})" if sanitized_by else "")
                )

    def _propagate_taint(self, root: Any) -> None:
        """Propagate taint through variable assignments and expressions."""
        assignment_types = {"assignment_expression", "augmented_assignment_expression"}
        assignments = find_nodes_by_types(root, assignment_types)

        # Multiple passes to handle cascading assignments
        for _ in range(3):
            changed = False
            for node in assignments:
                target = get_assignment_target(node, self.source_bytes)
                value_node = node.child_by_field_name("right")

                if not target or not value_node:
                    continue

                # Skip if target is already tainted from a source
                if target in self.tainted_vars and self.tainted_vars[target].source_line == get_line_number(node):
                    continue

                value_text = get_node_text(value_node, self.source_bytes)

                # AST-Based Cast Expression Sanitization (Type Casting)
                is_cast_sanitized = False
                if value_node.type == "cast_expression":
                    type_node = value_node.child_by_field_name("type")
                    if type_node:
                        cast_text = get_node_text(type_node, self.source_bytes).strip().lower()
                        if cast_text in ["(int)", "(integer)", "(float)", "(double)", "(real)", "(bool)", "(boolean)"]:
                            is_cast_sanitized = True

                # Taint Truncation: if the value comes from a DB fetch
                # function, do NOT propagate taint — DB output is trusted.
                is_db_fetch = any(p.search(value_text) for p in _DB_FETCH_REGEXES)
                if is_db_fetch:
                    # If the target was previously tainted, un-taint it.
                    if target in self.tainted_vars:
                        del self.tainted_vars[target]
                    continue

                # Check if value contains any tainted variables
                vars_in_value = find_variables_in_node(value_node, self.source_bytes)
                for var in vars_in_value:
                    if var in self.tainted_vars:
                        tainted_from = self.tainted_vars[var]
                        line = get_line_number(node)

                        # Check if value passes through a sanitizer
                        is_san = False
                        san_cat = None
                        if is_cast_sanitized:
                            is_san = True
                            san_cat = "type_cast"
                        elif is_sanitizer(value_text):
                            is_san = True
                            san_cat = get_sanitizer_category(value_text)
                        else:
                            for pat, rule in self._compiled_custom_sanitizers.items():
                                if pat.search(value_text):
                                    is_san = True
                                    san_cat = "custom_sanitizer"
                                    break

                        if is_san:
                            self.tainted_vars[target] = TaintedVariable(
                                name=target,
                                source=tainted_from.source,
                                source_line=tainted_from.source_line,
                                taint_path=tainted_from.taint_path + [
                                    f"{target} = {value_text} (line {line}) [SANITIZED by {san_cat}]"
                                ],
                                sanitized_by=value_text,
                                sanitizer_category=san_cat,
                                custom_rule=tainted_from.custom_rule,
                            )
                        else:
                            self.tainted_vars[target] = TaintedVariable(
                                name=target,
                                source=tainted_from.source,
                                source_line=tainted_from.source_line,
                                taint_path=tainted_from.taint_path + [
                                    f"{target} = {value_text} (line {line})"
                                ],
                                custom_rule=tainted_from.custom_rule,
                            )
                        changed = True
                        break

            if not changed:
                break

    def _check_sinks(self, root: Any) -> None:
        """Check if any tainted data reaches dangerous sinks."""
        call_types = {
            "function_call_expression",
            "member_call_expression",
            "scoped_call_expression",
        }
        calls = find_nodes_by_types(root, call_types)

        for node in calls:
            func_name = get_function_name(node, self.source_bytes)
            if not func_name:
                continue

            full_call = get_node_text(node, self.source_bytes)

            is_sink = False
            sink_cats = []
            matched_custom_rule = None

            if is_taint_sink(func_name):
                is_sink = True
                sink_cats = get_sink_categories(func_name)
            else:
                for pat, rule in self._compiled_custom_sinks.items():
                    if pat.search(full_call):
                        is_sink = True
                        sink_cats = [rule.subcategory or "custom_sink"]
                        matched_custom_rule = rule
                        break

            if not is_sink:
                continue

            # OOP Context Awareness: skip safe object types calling
            # generic method names (e.g., $form->execute()).
            if node.type == "member_call_expression":
                obj_node = node.child_by_field_name("object")
                if obj_node:
                    obj_text = get_node_text(obj_node, self.source_bytes)
                    if any(p.search(obj_text) for p in _SAFE_OBJECT_PATTERNS):
                        continue

            # Inline Sanitization Detection (full call text)
            if is_sanitizer(full_call) and any(is_effective_sanitizer(full_call, sc) for sc in sink_cats):
                continue
            
            # Check custom sanitizers
            custom_sanitized = any(pat.search(full_call) for pat in self._compiled_custom_sanitizers)
            if custom_sanitized:
                continue

            # Check if any arguments contain tainted variables
            args = get_function_arguments(node, self.source_bytes)
            args_node = node.child_by_field_name("arguments")

            if args_node:
                args_text = get_node_text(args_node, self.source_bytes)

                if is_sanitizer(args_text) and any(is_effective_sanitizer(args_text, sc) for sc in sink_cats):
                    continue
                if any(pat.search(args_text) for pat in self._compiled_custom_sanitizers):
                    continue

                arg_vars = find_variables_in_node(args_node, self.source_bytes)
                for var in arg_vars:
                    if var in self.tainted_vars:
                        tainted = self.tainted_vars[var]

                        # Logical Validation Awareness
                        var_escaped = re.escape(var.strip("$"))
                        # Check if it's inside isset()
                        if re.search(rf'isset\s*\([^)]*\${var_escaped}\b', full_call):
                            continue
                        # Check if it's used as an array key
                        if re.search(rf'\[[^\]]*\${var_escaped}\b', full_call):
                            continue

                        # Check if sanitization is effective for this sink
                        if tainted.sanitized_by:
                            effective = any(is_effective_sanitizer(tainted.sanitized_by, sc) for sc in sink_cats)
                            custom_effective = any(pat.search(tainted.sanitized_by) for pat in self._compiled_custom_sanitizers)
                            if effective or custom_effective:
                                continue

                        # OJS DAO Bindings Check: if func is retrieve,
                        # ensure the tainted var is in the SQL string (first arg).
                        # If it's only in the bindings (subsequent args), it's safe.
                        if func_name == "retrieve" and "sql_injection" in sink_cats:
                            first_arg_node = None
                            for child in args_node.children:
                                if child.type == "argument":
                                    first_arg_node = child
                                    break
                            if first_arg_node:
                                vars_in_first = find_variables_in_node(first_arg_node, self.source_bytes)
                                if var not in vars_in_first:
                                    continue  # Safe context, bound parameter

                        # Strict Sink-to-Rule Binding
                        if tainted.custom_rule:
                            if matched_custom_rule and matched_custom_rule.id == tainted.custom_rule.id:
                                pass # Valid
                            else:
                                continue # Skip: custom source didn't hit ITS intended custom sink

                        line = get_line_number(node)
                        self._create_finding(
                            tainted, func_name, full_call, line, sink_cats, matched_custom_rule
                        )
                        break

        # Also check echo/print statements (they're expression_statements)
        self._check_echo_sinks(root)

    def _check_echo_sinks(self, root: Any) -> None:
        """Check echo and print statements for tainted data."""
        echo_nodes = find_nodes_by_types(root, {"echo_statement", "print_intrinsic"})

        for node in echo_nodes:
            node_text = get_node_text(node, self.source_bytes)

            # Inline Sanitization Detection for echo/print
            if is_sanitizer(node_text) and is_effective_sanitizer(node_text, "xss"):
                continue

            vars_in_echo = find_variables_in_node(node, self.source_bytes)

            for var in vars_in_echo:
                if var in self.tainted_vars:
                    tainted = self.tainted_vars[var]

                    # Logical Validation Awareness
                    var_escaped = re.escape(var.strip("$"))
                    if re.search(rf'isset\s*\([^)]*\${var_escaped}\b', node_text):
                        continue
                    if re.search(rf'\[[^\]]*\${var_escaped}\b', node_text):
                        continue

                    if tainted.sanitized_by:
                        if is_effective_sanitizer(tainted.sanitized_by, "xss"):
                            continue
                        if any(pat.search(tainted.sanitized_by) for pat in self._compiled_custom_sanitizers):
                            continue

                    # Strict Sink-to-Rule Binding for generic echo
                    if tainted.custom_rule:
                        continue # Skip: a custom source should hit its specific custom sink, not generic echo

                    line = get_line_number(node)
                    self._create_finding(
                        tainted, "echo/print", node_text.strip(), line, ["xss"]
                    )
                    break

    def _create_finding(
        self,
        tainted: TaintedVariable,
        sink_name: str,
        sink_code: str,
        sink_line: int,
        sink_categories: list[str],
        matched_custom_rule: Rule | None = None,
    ) -> None:
        """Create a Finding from a taint-to-sink flow."""
        self._finding_counter += 1

        # Map sink category to CWE and OWASP
        cwe_map = {
            "sql_injection": ("CWE-89", "A03:2021"),
            "xss": ("CWE-79", "A03:2021"),
            "rce": ("CWE-78", "A03:2021"),
            "file_ops": ("CWE-22", "A01:2021"),
            "ssrf": ("CWE-918", "A10:2021"),
            "xxe": ("CWE-611", "A05:2021"),
            "deserialization": ("CWE-502", "A08:2021"),
            "header_injection": ("CWE-113", "A03:2021"),
            "ldap": ("CWE-90", "A03:2021"),
        }

        primary_cat = sink_categories[0] if sink_categories else "unknown"
        cwe, owasp = cwe_map.get(primary_cat, ("CWE-20", "A03:2021"))

        # Build subcategory name
        subcat_map = {
            "sql_injection": "injection",
            "xss": "injection",
            "rce": "injection",
            "file_ops": "file_ops",
            "ssrf": "misc",
            "xxe": "injection",
            "deserialization": "misc",
            "header_injection": "injection",
            "ldap": "injection",
        }
        subcategory = subcat_map.get(primary_cat, "misc")

        # Build human-readable name
        vuln_names = {
            "sql_injection": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "rce": "Remote Code Execution",
            "file_ops": "Path Traversal / File Inclusion",
            "ssrf": "Server-Side Request Forgery",
            "xxe": "XML External Entity",
            "deserialization": "Insecure Deserialization",
            "header_injection": "HTTP Header Injection",
            "ldap": "LDAP Injection",
        }
        vuln_name = vuln_names.get(primary_cat, primary_cat.replace("_", " ").title())

        taint_path = TaintPath(
            source=tainted.source,
            source_location=f"{self.filepath}:{tainted.source_line}",
            sink=sink_name,
            sink_location=f"{self.filepath}:{sink_line}",
            intermediate_steps=tainted.taint_path,
            sanitized=tainted.sanitized_by is not None,
        )

        snippet = get_code_snippet(self.filepath, sink_line, context=2)

        # Use the matched rule (from sink or source) for specific reporting if available
        rule_to_use = matched_custom_rule or tainted.custom_rule

        if rule_to_use:
            finding = Finding(
                id=f"TAINT-{self._finding_counter:04d}",
                rule_id=rule_to_use.id,
                name=rule_to_use.name,
                description=(
                    f"Data from user input ({tainted.source}) flows into "
                    f"a dangerous function ({sink_name}) without adequate sanitization. "
                    f"Matches rule {rule_to_use.id}."
                ),
                severity=Severity.from_string(rule_to_use.severity),
                category=Category.SOURCE_CODE,
                subcategory=rule_to_use.subcategory,
                file_path=self.filepath,
                line_start=min(tainted.source_line, sink_line),
                line_end=max(tainted.source_line, sink_line),
                code_snippet=snippet,
                cwe=rule_to_use.cwe,
                owasp=rule_to_use.owasp,
                cve_references=rule_to_use.cve_references,
                taint_path=taint_path,
                remediation=rule_to_use.remediation,
            )
        else:
            finding = Finding(
                id=f"TAINT-{self._finding_counter:04d}",
                rule_id=f"OJS-SC-{primary_cat.upper().replace('_', '')}-TAINT",
                name=f"{vuln_name} via tainted input",
                description=(
                    f"Data from user input ({tainted.source}) flows into "
                    f"a dangerous function ({sink_name}) without adequate sanitization."
                ),
                severity=self._get_severity(primary_cat, tainted.sanitized_by is not None),
                category=Category.SOURCE_CODE,
                subcategory=subcategory,
                file_path=self.filepath,
                line_start=min(tainted.source_line, sink_line),
                line_end=max(tainted.source_line, sink_line),
                code_snippet=snippet,
                cwe=cwe,
                owasp=owasp,
                taint_path=taint_path,
                remediation=self._get_remediation(primary_cat),
            )

        self.findings.append(finding)

    @staticmethod
    def _get_severity(sink_category: str, is_partially_sanitized: bool) -> Severity:
        """Determine finding severity based on sink category."""
        severity_map = {
            "sql_injection": Severity.CRITICAL,
            "rce": Severity.CRITICAL,
            "xxe": Severity.HIGH,
            "xss": Severity.HIGH,
            "file_ops": Severity.HIGH,
            "ssrf": Severity.HIGH,
            "deserialization": Severity.HIGH,
            "header_injection": Severity.MEDIUM,
            "ldap": Severity.HIGH,
        }
        severity = severity_map.get(sink_category, Severity.MEDIUM)

        # Downgrade by one level if partially sanitized
        if is_partially_sanitized:
            downgrade = {
                Severity.CRITICAL: Severity.HIGH,
                Severity.HIGH: Severity.MEDIUM,
                Severity.MEDIUM: Severity.LOW,
                Severity.LOW: Severity.INFO,
                Severity.INFO: Severity.INFO,
            }
            severity = downgrade[severity]

        return severity

    @staticmethod
    def _get_remediation(sink_category: str) -> str:
        """Get remediation guidance for a sink category."""
        remediations = {
            "sql_injection": (
                "Use prepared statements or parameterized queries. "
                "If using OJS DAO, use $this->_driver->escapeString() "
                "or intval() for integer parameters."
            ),
            "xss": (
                "Apply htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before output. "
                "In OJS Smarty templates, use |escape modifier. "
                "For rich text, use PKPString::stripUnsafeHtml()."
            ),
            "rce": (
                "Avoid using exec(), system(), or eval() with user input. "
                "Use escapeshellarg() and escapeshellcmd() if shell execution "
                "is absolutely necessary."
            ),
            "file_ops": (
                "Use basename() to strip directory components. "
                "Validate paths with realpath() and ensure they're within "
                "the expected directory. Never use user input in include/require."
            ),
            "ssrf": (
                "Validate and whitelist allowed URLs/hosts. "
                "Block internal/private IP ranges. "
                "Use a URL parser to enforce allowed schemes (http/https only)."
            ),
            "xxe": (
                "Disable external entity loading: "
                "libxml_disable_entity_loader(true) and use LIBXML_NOENT flag."
            ),
            "deserialization": (
                "Avoid unserialize() with user input. "
                "Use json_decode() instead. If unserialize is required, "
                "use allowed_classes option (PHP 7+)."
            ),
            "header_injection": (
                "Validate and sanitize header values. "
                "Remove newline characters (\\r\\n) from user input "
                "before passing to header() or setcookie()."
            ),
            "ldap": (
                "Use ldap_escape() (PHP 5.6+) to sanitize user input "
                "before LDAP queries."
            ),
        }
        return remediations.get(sink_category, "Review and sanitize user input before use.")
