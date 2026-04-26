"""Rule data model for OJS-SAST security rules."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TaintRuleConfig:
    """Taint analysis configuration within a rule."""
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)


@dataclass
class PatternMatchConfig:
    """Pattern matching configuration within a rule."""
    type: str = "regex"  # "regex" or "ast_pattern"
    patterns: list[str] = field(default_factory=list)
    require_absence: Optional[str] = None  # Pattern that must be ABSENT for a match to trigger


@dataclass
class ConfigCheckCondition:
    """Condition for configuration-based rules."""
    field_path: str = ""           # e.g. "database.password"
    condition: str = ""            # "empty", "equals", "not_in", "contains", "missing", "regex_match"
    value: Optional[str] = None    # expected value for "equals"
    allowed_values: list[str] = field(default_factory=list)  # for "not_in"
    pattern: Optional[str] = None  # for "regex_match"
    note: str = ""


@dataclass
class Rule:
    """A security scanning rule."""
    id: str
    name: str
    description: str
    severity: str                  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str                  # source_code | config | uploaded_file
    subcategory: str               # injection, auth, exposure, etc.
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cve_references: list[str] = field(default_factory=list)
    ojs_versions_affected: str = "all"
    dangerous_extensions: list[str] = field(default_factory=list)
    taint_analysis: Optional[TaintRuleConfig] = None
    pattern_match: Optional[PatternMatchConfig] = None
    config_check: Optional[ConfigCheckCondition] = None
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    false_positive_notes: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        """Create a Rule from a dictionary (parsed from YAML)."""
        taint_data = data.get("taint_analysis")
        taint_config = None
        if taint_data and isinstance(taint_data, dict):
            taint_config = TaintRuleConfig(
                sources=taint_data.get("sources", []),
                sinks=taint_data.get("sinks", []),
                sanitizers=taint_data.get("sanitizers", []),
            )

        pattern_data = data.get("pattern_match")
        pattern_config = None
        if pattern_data and isinstance(pattern_data, dict):
            pattern_config = PatternMatchConfig(
                type=pattern_data.get("type", "regex"),
                patterns=pattern_data.get("patterns", []),
                require_absence=pattern_data.get("require_absence"),
            )

        config_data = data.get("config_check")
        config_check = None
        if config_data and isinstance(config_data, dict):
            config_check = ConfigCheckCondition(
                field_path=config_data.get("field", config_data.get("field_path", "")),
                condition=config_data.get("condition", ""),
                value=config_data.get("value"),
                allowed_values=config_data.get("allowed_values", []),
                pattern=config_data.get("pattern"),
                note=config_data.get("note", ""),
            )

        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            severity=data.get("severity", "MEDIUM"),
            category=data.get("category", ""),
            subcategory=data.get("subcategory", ""),
            cwe=data.get("cwe"),
            owasp=data.get("owasp"),
            cve_references=data.get("cve_references", []),
            ojs_versions_affected=data.get("ojs_versions_affected", "all"),
            dangerous_extensions=data.get("dangerous_extensions", []),
            taint_analysis=taint_config,
            pattern_match=pattern_config,
            config_check=config_check,
            include_paths=data.get("include_paths", []),
            exclude_paths=data.get("exclude_paths", []),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            false_positive_notes=data.get("false_positive_notes", ""),
        )

    def to_dict(self) -> dict:
        result: dict = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "subcategory": self.subcategory,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cve_references": self.cve_references,
            "ojs_versions_affected": self.ojs_versions_affected,
            "dangerous_extensions": self.dangerous_extensions,
            "include_paths": self.include_paths,
            "exclude_paths": self.exclude_paths,
            "remediation": self.remediation,
            "references": self.references,
            "false_positive_notes": self.false_positive_notes,
        }
        if self.taint_analysis:
            result["taint_analysis"] = {
                "sources": self.taint_analysis.sources,
                "sinks": self.taint_analysis.sinks,
                "sanitizers": self.taint_analysis.sanitizers,
            }
        if self.pattern_match:
            result["pattern_match"] = {
                "type": self.pattern_match.type,
                "patterns": self.pattern_match.patterns,
            }
        if self.config_check:
            result["config_check"] = {
                "field": self.config_check.field_path,
                "condition": self.config_check.condition,
                "value": self.config_check.value,
                "allowed_values": self.config_check.allowed_values,
                "note": self.config_check.note,
            }
        return result
