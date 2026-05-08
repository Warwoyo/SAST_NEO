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
    # Keep original raw patterns for reference (before normalization)
    raw_patterns: list = field(default_factory=list)


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
    # Extended fields from scientific ruleset
    confidence: str = ""
    scan_scope: Optional[dict] = None
    false_positive_conditions: list[dict] = field(default_factory=list)
    config_section: str = ""
    config_key: str = ""
    config_directive: str = ""
    standard_references: list[dict] = field(default_factory=list)
    related_cve: list[str] = field(default_factory=list)
    insecure_example: str = ""
    secure_example: str = ""
    # Extended fields from scientific ruleset
    confidence: str = ""
    scan_scope: Optional[dict] = None
    false_positive_conditions: list[dict] = field(default_factory=list)
    config_section: str = ""
    config_key: str = ""
    config_directive: str = ""
    standard_references: list[dict] = field(default_factory=list)
    related_cve: list[str] = field(default_factory=list)
    insecure_example: str = ""
    secure_example: str = ""

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
            raw_patterns = pattern_data.get("patterns", [])
            pattern_type = pattern_data.get("type", "regex")
            # Normalize patterns: extract 'query' from dict-type patterns
            normalized = []
            for p in raw_patterns:
                if isinstance(p, str):
                    normalized.append(p)
                elif isinstance(p, dict):
                    query = p.get("query", "")
                    if query:
                        normalized.append(query.strip())
            raw_patterns = pattern_data.get("patterns", [])
            pattern_type = pattern_data.get("type", "regex")
            # Normalize patterns: extract 'query' from dict-type patterns
            normalized = []
            for p in raw_patterns:
                if isinstance(p, str):
                    normalized.append(p)
                elif isinstance(p, dict):
                    query = p.get("query", "")
                    if query:
                        normalized.append(query.strip())
            pattern_config = PatternMatchConfig(
                type=pattern_type,
                patterns=normalized,
                require_absence=pattern_data.get("require_absence"),
                raw_patterns=raw_patterns,
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
            # Extended fields from scientific ruleset
            confidence=data.get("confidence", ""),
            scan_scope=data.get("scan_scope"),
            false_positive_conditions=data.get("false_positive_conditions", []),
            config_section=data.get("config_section", ""),
            config_key=data.get("config_key", ""),
            config_directive=data.get("config_directive", ""),
            standard_references=data.get("standard_references", []),
            related_cve=data.get("related_cve", []),
            insecure_example=data.get("insecure_example", ""),
            secure_example=data.get("secure_example", ""),
            # Extended fields from scientific ruleset
            confidence=data.get("confidence", ""),
            scan_scope=data.get("scan_scope"),
            false_positive_conditions=data.get("false_positive_conditions", []),
            config_section=data.get("config_section", ""),
            config_key=data.get("config_key", ""),
            config_directive=data.get("config_directive", ""),
            standard_references=data.get("standard_references", []),
            related_cve=data.get("related_cve", []),
            insecure_example=data.get("insecure_example", ""),
            secure_example=data.get("secure_example", ""),
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
        # Extended fields (only include if non-empty)
        if self.confidence:
            result["confidence"] = self.confidence
        if self.scan_scope:
            result["scan_scope"] = self.scan_scope
        if self.false_positive_conditions:
            result["false_positive_conditions"] = self.false_positive_conditions
        if self.config_section:
            result["config_section"] = self.config_section
        if self.config_key:
            result["config_key"] = self.config_key
        if self.config_directive:
            result["config_directive"] = self.config_directive
        if self.standard_references:
            result["standard_references"] = self.standard_references
        if self.related_cve:
            result["related_cve"] = self.related_cve
        if self.insecure_example:
            result["insecure_example"] = self.insecure_example
        if self.secure_example:
            result["secure_example"] = self.secure_example
        # Extended fields (only include if non-empty)
        if self.confidence:
            result["confidence"] = self.confidence
        if self.scan_scope:
            result["scan_scope"] = self.scan_scope
        if self.false_positive_conditions:
            result["false_positive_conditions"] = self.false_positive_conditions
        if self.config_section:
            result["config_section"] = self.config_section
        if self.config_key:
            result["config_key"] = self.config_key
        if self.config_directive:
            result["config_directive"] = self.config_directive
        if self.standard_references:
            result["standard_references"] = self.standard_references
        if self.related_cve:
            result["related_cve"] = self.related_cve
        if self.insecure_example:
            result["insecure_example"] = self.insecure_example
        if self.secure_example:
            result["secure_example"] = self.secure_example
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
                "require_absence": self.pattern_match.require_absence,
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
