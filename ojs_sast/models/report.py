"""Report data model for OJS-SAST scan results."""

from dataclasses import dataclass, field
from typing import Optional

from ojs_sast.models.finding import Finding


@dataclass
class ScanReport:
    """Complete scan report containing all findings and metadata."""
    scan_id: str
    timestamp: str
    ojs_version: Optional[str]
    ojs_path: str
    scan_duration_seconds: float
    findings: list[Finding]
    summary: dict                     # {CRITICAL: n, HIGH: n, ...}
    scanner_version: str
    categories_scanned: list[str]
    files_scanned: int
    rules_loaded: int

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "ojs_version": self.ojs_version,
            "ojs_path": self.ojs_path,
            "scan_duration_seconds": self.scan_duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "scanner_version": self.scanner_version,
            "categories_scanned": self.categories_scanned,
            "files_scanned": self.files_scanned,
            "rules_loaded": self.rules_loaded,
        }

    @staticmethod
    def compute_summary(findings: list[Finding]) -> dict:
        """Compute severity summary from list of findings."""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            severity_key = f.severity.value
            if severity_key in summary:
                summary[severity_key] += 1
        return summary
