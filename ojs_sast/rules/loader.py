"""YAML rule loader for OJS-SAST."""

import os
from pathlib import Path

import yaml

from ojs_sast.models.rule import Rule
from ojs_sast.utils.logger import logger


class RuleLoader:
    """Loads and manages security scanning rules from YAML files."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._rules_by_id: dict[str, Rule] = {}
        self._loaded_files: list[str] = []

    @property
    def rules(self) -> list[Rule]:
        """Return all loaded rules."""
        return self._rules

    @property
    def rules_count(self) -> int:
        """Return the total number of loaded rules."""
        return len(self._rules)

    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a specific rule by its ID."""
        return self._rules_by_id.get(rule_id)

    def get_rules_by_category(self, category: str) -> list[Rule]:
        """Get all rules for a specific category."""
        return [r for r in self._rules if r.category == category]

    def get_rules_by_subcategory(self, category: str, subcategory: str) -> list[Rule]:
        """Get rules for a specific category and subcategory."""
        return [
            r for r in self._rules
            if r.category == category and r.subcategory == subcategory
        ]

    def get_rules_by_severity(self, severity: str) -> list[Rule]:
        """Get all rules matching a minimum severity level."""
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_level = severity_order.get(severity.upper(), 0)
        return [
            r for r in self._rules
            if severity_order.get(r.severity, 0) >= min_level
        ]

    def load_directory(self, directory: str) -> int:
        """Load all YAML rule files from a directory recursively.

        Args:
            directory: Path to the rules directory.

        Returns:
            Number of rules loaded from this directory.
        """
        directory = os.path.abspath(directory)
        if not os.path.isdir(directory):
            logger.warning(f"Rules directory not found: {directory}")
            return 0

        count = 0
        for root, _dirs, files in os.walk(directory):
            for filename in sorted(files):
                if filename.endswith((".yaml", ".yml")):
                    filepath = os.path.join(root, filename)
                    loaded = self.load_file(filepath)
                    count += loaded

        return count

    def load_file(self, filepath: str) -> int:
        """Load rules from a single YAML file.

        Args:
            filepath: Path to the YAML rule file.

        Returns:
            Number of rules loaded from this file.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            logger.error(f"Failed to load rule file {filepath}: {e}")
            return 0

        if not data:
            return 0

        # Support both top-level lists and {'rules': [...]} or {'checks': [...]}
        rules_data: list[dict] = []
        if isinstance(data, dict):
            rules_data = data.get("rules", data.get("checks", []))
            if not rules_data and "id" in data:
                # Single rule at top level
                rules_data = [data]
        elif isinstance(data, list):
            rules_data = data

        count = 0
        for rule_data in rules_data:
            if not isinstance(rule_data, dict) or "id" not in rule_data:
                continue

            try:
                # Infer category/subcategory from directory structure if not specified
                if not rule_data.get("category"):
                    rule_data["category"] = _infer_category(filepath)
                if not rule_data.get("subcategory"):
                    rule_data["subcategory"] = _infer_subcategory(filepath)

                rule = Rule.from_dict(rule_data)

                if rule.id in self._rules_by_id:
                    logger.warning(
                        f"Duplicate rule ID '{rule.id}' in {filepath}, skipping"
                    )
                    continue

                self._rules.append(rule)
                self._rules_by_id[rule.id] = rule
                count += 1
            except (KeyError, ValueError) as e:
                logger.warning(f"Invalid rule in {filepath}: {e}")

        if count > 0:
            self._loaded_files.append(filepath)
            logger.debug(f"Loaded {count} rules from {Path(filepath).name}")

        return count

    def load_all_builtin_rules(self) -> int:
        """Load all built-in rules from the categories directories.

        Returns:
            Total number of rules loaded.
        """
        base_dir = Path(__file__).parent.parent / "categories"
        total = 0

        # Source code rules
        sc_rules = base_dir / "source_code" / "rules"
        if sc_rules.is_dir():
            total += self.load_directory(str(sc_rules))

        # Config rules
        cfg_rules = base_dir / "config" / "rules"
        if cfg_rules.is_dir():
            total += self.load_directory(str(cfg_rules))

        # Uploaded file rules
        uf_rules = base_dir / "uploaded_file" / "rules"
        if uf_rules.is_dir():
            total += self.load_directory(str(uf_rules))

        logger.info(f"Total rules loaded: {total}")
        return total


def _infer_category(filepath: str) -> str:
    """Infer rule category from the file path."""
    path_lower = filepath.replace("\\", "/").lower()
    if "source_code" in path_lower:
        return "source_code"
    if "config" in path_lower:
        return "config"
    if "uploaded_file" in path_lower:
        return "uploaded_file"
    return ""


def _infer_subcategory(filepath: str) -> str:
    """Infer rule subcategory from the parent directory name."""
    parent = os.path.basename(os.path.dirname(filepath))
    # If parent is 'rules', go one more level up
    if parent == "rules":
        parent = os.path.basename(
            os.path.dirname(os.path.dirname(filepath))
        )
    return parent
