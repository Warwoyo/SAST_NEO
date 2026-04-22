"""Finding data model for OJS-SAST scan results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Create Severity from string, case-insensitive."""
        try:
            return cls(value.upper())
        except ValueError:
            return cls.MEDIUM

    def __lt__(self, other: "Severity") -> bool:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self] < order[other]


class Category(Enum):
    """Scan category types."""
    SOURCE_CODE = "source_code"
    CONFIG = "config"
    UPLOADED_FILE = "uploaded_file"


@dataclass
class TaintPath:
    """Represents the data-flow path from taint source to sink."""
    source: str
    source_location: str       # "file.php:42"
    sink: str
    sink_location: str         # "file.php:78"
    intermediate_steps: list[str] = field(default_factory=list)
    sanitized: bool = False

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "source_location": self.source_location,
            "sink": self.sink,
            "sink_location": self.sink_location,
            "intermediate_steps": self.intermediate_steps,
            "sanitized": self.sanitized,
        }

    def to_display_string(self) -> str:
        """Human-readable taint path for CLI output."""
        parts = [self.source]
        parts.extend(self.intermediate_steps)
        parts.append(self.sink)
        return " → ".join(parts)


@dataclass
class Finding:
    """A single security finding from the scan."""
    id: str
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    subcategory: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cve_references: list[str] = field(default_factory=list)
    taint_path: Optional[TaintPath] = None
    remediation: str = ""
    false_positive_likelihood: str = "LOW"
    references: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cve_references": self.cve_references,
            "taint_path": self.taint_path.to_dict() if self.taint_path else None,
            "remediation": self.remediation,
            "false_positive_likelihood": self.false_positive_likelihood,
            "references": self.references,
            "metadata": self.metadata,
        }
