"""OJS config.inc.php parser.

Parses the OJS configuration file which uses an INI-like format
wrapped in PHP tags.
"""

import re
from typing import Optional

from ojs_sast.utils.file_utils import read_file_safe
from ojs_sast.utils.logger import logger


class OJSConfigParser:
    """Parser for OJS config.inc.php files."""

    def __init__(self) -> None:
        self.sections: dict[str, dict[str, str]] = {}
        self.raw_content: str = ""
        self.filepath: str = ""

    def parse(self, filepath: str) -> dict[str, dict[str, str]]:
        """Parse an OJS config.inc.php file.

        Args:
            filepath: Path to config.inc.php.

        Returns:
            Dictionary of sections with their key-value pairs.
            e.g., {"database": {"host": "localhost", "driver": "mysqli"}}
        """
        self.filepath = filepath
        content = read_file_safe(filepath)
        if not content:
            logger.warning(f"Cannot read config file: {filepath}")
            return {}

        self.raw_content = content
        self.sections = {}

        current_section = "general"
        self.sections[current_section] = {}

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines, comments, and PHP tags
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            if line.startswith("<?") or line.startswith("?>"):
                continue

            # Section header: [section_name]
            section_match = re.match(r"^\[(\w+)\]", line)
            if section_match:
                current_section = section_match.group(1)
                if current_section not in self.sections:
                    self.sections[current_section] = {}
                continue

            # Key = Value pair
            kv_match = re.match(r"^(\w+)\s*=\s*(.*)", line)
            if kv_match:
                key = kv_match.group(1).strip()
                value = kv_match.group(2).strip()
                value = self._strip_inline_comment(value).strip()
                # Remove surrounding quotes
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("\"", "'"):
                    value = value[1:-1]
                self.sections[current_section][key] = value

        logger.debug(f"Parsed {len(self.sections)} sections from {filepath}")
        return self.sections

    def get_value(self, section: str, key: str) -> Optional[str]:
        """Get a specific config value.

        Args:
            section: Section name (e.g., 'database').
            key: Key name (e.g., 'host').

        Returns:
            The value or None if not found.
        """
        return self.sections.get(section, {}).get(key)

    def get_section(self, section: str) -> dict[str, str]:
        """Get all values in a section."""
        return self.sections.get(section, {})

    def has_section(self, section: str) -> bool:
        """Check if a section exists."""
        return section in self.sections

    def has_value(self, section: str, key: str) -> bool:
        """Check if a key exists in a section."""
        return key in self.sections.get(section, {})

    @staticmethod
    def _strip_inline_comment(value: str) -> str:
        """Strip inline comments outside of quotes (INI style)."""
        in_single = False
        in_double = False

        for i, ch in enumerate(value):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch in (";", "#") and not in_single and not in_double:
                return value[:i].rstrip()

        return value
