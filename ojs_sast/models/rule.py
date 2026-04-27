"""Rule data model for OJS-SAST security rules."""

from dataclasses import dataclass, field
from typing import Optional



@dataclass
class PatternMatchConfig:
    """Pattern matching configuration within a rule."""
    type: str = "regex"  # "regex" or "ast_pattern"
    patterns: list[str] = field(default_factory=list)
    require_absence: Optional[str] = None  # Pattern that must be ABSENT for a match to trigger



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
    pattern_match: Optional[PatternMatchConfig] = None
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    false_positive_notes: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        """Create a Rule from a dictionary (parsed from YAML)."""
        pattern_data = data.get("pattern_match")
        pattern_config = None
        if pattern_data and isinstance(pattern_data, dict):
            pattern_config = PatternMatchConfig(
                type=pattern_data.get("type", "regex"),
                patterns=pattern_data.get("patterns", []),
                require_absence=pattern_data.get("require_absence"),
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
            pattern_match=pattern_config,
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
            "include_paths": self.include_paths,
            "exclude_paths": self.exclude_paths,
            "remediation": self.remediation,
            "references": self.references,
            "false_positive_notes": self.false_positive_notes,
        }
        if self.pattern_match:
            result["pattern_match"] = {
                "type": self.pattern_match.type,
                "patterns": self.pattern_match.patterns,
                "require_absence": self.pattern_match.require_absence,
            }
        return result
