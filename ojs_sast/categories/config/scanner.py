"""Configuration scanner for OJS-SAST.

Scans OJS config.inc.php, Nginx, and Apache configurations
against security rules.
"""

import os
import re

from ojs_sast.categories.config.parsers.apache_parser import ApacheConfigParser
from ojs_sast.categories.config.parsers.nginx_parser import NginxConfigParser
from ojs_sast.categories.config.parsers.ojs_config import OJSConfigParser
from ojs_sast.models.finding import Category, Finding, Severity
from ojs_sast.models.rule import Rule
from ojs_sast.utils.file_utils import read_file_safe
from ojs_sast.utils.logger import logger


class ConfigScanner:
    """Scans configuration files for security issues."""

    def __init__(
        self,
        rules: list[Rule],
        target_path: str,
        nginx_config: str | None = None,
        apache_config: str | None = None,
        ojs_config_path: str | None = None,
    ) -> None:
        self.rules = [r for r in rules if r.category in (
            "config", "configuration", "webserver_configuration"
        )]
        self.target_path = os.path.abspath(target_path)
        self.nginx_config = nginx_config
        self.apache_config = apache_config
        self.ojs_config_path = ojs_config_path
        self.findings: list[Finding] = []
        self._finding_counter = 0
        self._breached_passwords: set[str] | None = None

    def _load_breached_passwords(self) -> set[str]:
        if self._breached_passwords is not None:
            return self._breached_passwords

        self._breached_passwords = set()
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
        pw_file = os.path.join(data_dir, "breached_passwords.txt")
        
        content = read_file_safe(pw_file)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line:
                    self._breached_passwords.add(line)
        return self._breached_passwords

    def scan(self) -> list[Finding]:
        """Run all configuration scans."""
        self.findings = []
        logger.info("Scanning configurations...")

        # Scan OJS config
        config_path = self.ojs_config_path
        if not config_path:
            config_path = os.path.join(self.target_path, "config.inc.php")

        if config_path and os.path.isfile(config_path):
            self._scan_ojs_config(config_path)
        else:
            logger.warning("Skipping OJS config scan ('config.inc.php' not found), continuing to web server configuration scans...")

        # Scan Nginx config
        if self.nginx_config and os.path.isfile(self.nginx_config):
            self._scan_nginx_config(self.nginx_config)

        # Scan Apache config
        if self.apache_config and os.path.isfile(self.apache_config):
            self._scan_apache_config(self.apache_config)

        # Also look for .htaccess in OJS root
        htaccess = os.path.join(self.target_path, ".htaccess")
        if os.path.isfile(htaccess):
            self._scan_apache_config(htaccess)

        logger.info(f"Config scan complete: {len(self.findings)} findings")
        return self.findings

    def _scan_ojs_config(self, config_path: str) -> None:
        """Scan OJS config.inc.php against rules."""
        parser = OJSConfigParser()
        sections = parser.parse(config_path)

        if not sections:
            return

        # Check for breached database password
        db_password = parser.get_value("database", "password")
        if db_password and db_password.strip():
            breached_passwords = self._load_breached_passwords()
            if db_password in breached_passwords:
                self._finding_counter += 1
                self.findings.append(Finding(
                    id=f"CONFIG-{self._finding_counter:04d}",
                    rule_id="OJS-CONF-BREACH-001",
                    name="Breached Database Password Detected",
                    description=f"The database password was found in a known breached passwords list. This poses a severe risk.",
                    severity=Severity.CRITICAL,
                    category=Category.CONFIG,
                    subcategory="database",
                    file_path=config_path,
                    line_start=0,
                    line_end=0,
                    code_snippet=f"[database]\npassword = {db_password}",
                    cwe="CWE-521",
                    owasp="A07:2021",
                    remediation="Change the database password to a strong, unique, and randomly generated value.",
                ))

        ojs_rules = [r for r in self.rules if (
            r.subcategory in (
                "ojs", "database", "security_settings", "email", "files",
            )
            or (
                r.category == "configuration"
                and r.subcategory in (
                    "cryptography", "input_validation", "network_access",
                    "network_trust", "session_security", "transport_security",
                    "access_control", "authentication", "information_disclosure",
                    "file_permissions", "availability",
                )
            )
        )]

        for rule in ojs_rules:
            if rule.config_check:
                self._evaluate_config_check(rule, parser, config_path)
            if rule.pattern_match:
                self._scan_config_patterns(rule, config_path)

    def _scan_nginx_config(self, filepath: str) -> None:
        """Scan Nginx configuration against rules."""
        parser = NginxConfigParser()
        parser.parse(filepath)

        nginx_rules = [r for r in self.rules if (
            r.subcategory in ("nginx", "nginx_security")
            or (
                r.category == "webserver_configuration"
                and r.subcategory in (
                    "file_upload_security", "sensitive_file_exposure",
                    "cryptographic_configuration", "security_headers",
                    "transport_security", "information_disclosure",
                    "access_control", "denial_of_service", "nginx_specific",
                )
            )
        )]

        for rule in nginx_rules:
            if rule.pattern_match:
                self._scan_config_patterns(rule, filepath)
            if rule.config_check:
                self._evaluate_webserver_check(rule, parser, filepath)

    def _scan_apache_config(self, filepath: str) -> None:
        """Scan Apache configuration against rules."""
        parser = ApacheConfigParser()
        parser.parse(filepath)

        apache_rules = [r for r in self.rules if r.subcategory in ("apache", "apache_security")]

        for rule in apache_rules:
            if rule.pattern_match:
                self._scan_config_patterns(rule, filepath)
            if rule.config_check:
                self._evaluate_webserver_check(rule, parser, filepath, is_apache=True)

    def _evaluate_config_check(
        self,
        rule: Rule,
        parser: OJSConfigParser,
        filepath: str,
    ) -> None:
        """Evaluate a config check condition against parsed OJS config."""
        check = rule.config_check
        if not check:
            return

        # Parse field path: "database.password" -> section="database", key="password"
        parts = check.field_path.split(".", 1)
        if len(parts) != 2:
            return

        section, key = parts
        value = parser.get_value(section, key)

        triggered = False

        if check.condition == "empty":
            triggered = value is None or value.strip() == ""
        elif check.condition == "equals":
            triggered = value == check.value
        elif check.condition == "not_in":
            triggered = value is not None and value not in check.allowed_values
        elif check.condition == "contains":
            triggered = value is not None and check.value is not None and check.value in value
        elif check.condition == "missing":
            triggered = not parser.has_value(section, key)
        elif check.condition == "not_equals":
            triggered = value is not None and value != check.value
        elif check.condition == "regex_match":
            if value and check.pattern:
                triggered = bool(re.search(check.pattern, value))

        if triggered:
            self._create_config_finding(rule, filepath, f"[{section}] {key} = {value or '(not set)'}")

    def _evaluate_webserver_check(
        self,
        rule: Rule,
        parser: NginxConfigParser | ApacheConfigParser,
        filepath: str,
        is_apache: bool = False,
    ) -> None:
        """Evaluate config check for web server configurations."""
        check = rule.config_check
        if not check:
            return

        directive_name = check.field_path
        value = parser.get_directive_value(directive_name)

        triggered = False

        if check.condition == "missing":
            triggered = not parser.has_directive(directive_name)
        elif check.condition == "empty":
            triggered = value is None or value.strip() == ""
        elif check.condition == "contains":
            triggered = value is not None and check.value is not None and check.value in value
        elif check.condition == "not_contains":
            triggered = value is None or (check.value is not None and check.value not in (value or ""))
        elif check.condition == "equals":
            triggered = value == check.value

        if triggered:
            display = f"{directive_name} = {value or '(not set)'}"
            self._create_config_finding(rule, filepath, display)

    def _scan_config_patterns(self, rule: Rule, filepath: str) -> None:
        """Run regex pattern matching on config files."""
        content = read_file_safe(filepath)
        if not content or not rule.pattern_match:
            return

        for pattern in rule.pattern_match.patterns:
            try:
                for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                    line_num = content[:match.start()].count("\n") + 1
                    matched = match.group(0)
                    self._create_config_finding(rule, filepath, matched, line_num)
            except re.error:
                pass

    def _create_config_finding(
        self,
        rule: Rule,
        filepath: str,
        context: str,
        line: int = 0,
    ) -> None:
        """Create a Finding from a config check result."""
        self._finding_counter += 1

        finding = Finding(
            id=f"CONFIG-{self._finding_counter:04d}",
            rule_id=rule.id,
            name=rule.name,
            description=rule.description,
            severity=Severity.from_string(rule.severity),
            category=Category.CONFIG,
            subcategory=rule.subcategory,
            file_path=filepath,
            line_start=line,
            line_end=line,
            code_snippet=context,
            cwe=rule.cwe,
            owasp=rule.owasp,
            remediation=rule.remediation,
            references=rule.references,
        )
        self.findings.append(finding)
