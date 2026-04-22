"""Rule schema validator for OJS-SAST."""

from ojs_sast.models.rule import Rule
from ojs_sast.utils.logger import logger

REQUIRED_FIELDS = {"id", "name", "severity"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CATEGORIES = {"source_code", "config", "uploaded_file"}


class RuleValidator:
    """Validates rule definitions for completeness and correctness."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def validate_rules(self, rules: list[Rule]) -> bool:
        self.errors = []
        self.warnings = []
        seen_ids: set[str] = set()
        for rule in rules:
            self._validate_rule(rule, seen_ids)
        if self.errors:
            for err in self.errors:
                logger.error(f"Rule validation error: {err}")
        return len(self.errors) == 0

    def _validate_rule(self, rule: Rule, seen_ids: set[str]) -> None:
        if not rule.id:
            self.errors.append("Rule missing 'id' field")
            return
        if not rule.name:
            self.errors.append(f"Rule {rule.id}: missing 'name'")
        if rule.id in seen_ids:
            self.errors.append(f"Duplicate rule ID: {rule.id}")
        seen_ids.add(rule.id)
        if rule.severity and rule.severity not in VALID_SEVERITIES:
            self.errors.append(f"Rule {rule.id}: invalid severity '{rule.severity}'")
        if rule.category and rule.category not in VALID_CATEGORIES:
            self.warnings.append(f"Rule {rule.id}: unknown category '{rule.category}'")
        if rule.category == "source_code":
            if not rule.taint_analysis and not rule.pattern_match:
                self.warnings.append(f"Rule {rule.id}: no taint_analysis or pattern_match")
        if rule.category == "config":
            if not rule.config_check and not rule.pattern_match:
                self.warnings.append(f"Rule {rule.id}: no config_check or pattern_match")
