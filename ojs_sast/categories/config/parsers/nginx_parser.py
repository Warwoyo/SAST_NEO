"""Nginx configuration parser."""

import re
from dataclasses import dataclass, field

from ojs_sast.utils.file_utils import read_file_safe
from ojs_sast.utils.logger import logger


@dataclass
class NginxDirective:
    """A parsed Nginx directive."""
    name: str
    args: str
    line: int
    block_context: str = ""  # parent block (server, location, etc.)


class NginxConfigParser:
    """Parser for Nginx configuration files."""

    def __init__(self) -> None:
        self.directives: list[NginxDirective] = []
        self.raw_content: str = ""
        self.filepath: str = ""

    def parse(self, filepath: str) -> list[NginxDirective]:
        """Parse an Nginx configuration file.

        Args:
            filepath: Path to the Nginx config file.

        Returns:
            List of parsed directives.
        """
        self.filepath = filepath
        content = read_file_safe(filepath)
        if not content:
            logger.warning(f"Cannot read Nginx config: {filepath}")
            return []

        self.raw_content = content
        self.directives = []

        context_stack: list[str] = []
        current_context = "main"

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Track block context
            block_match = re.match(r"^(server|location|http|upstream|events)\s*(.*?)\s*\{", stripped)
            if block_match:
                context_stack.append(current_context)
                block_type = block_match.group(1)
                block_args = block_match.group(2).strip()
                current_context = f"{block_type} {block_args}".strip()
                self.directives.append(NginxDirective(
                    name=block_type,
                    args=block_args,
                    line=line_num,
                    block_context=current_context,
                ))
                continue

            if "}" in stripped:
                if context_stack:
                    current_context = context_stack.pop()
                continue

            # Parse directive: name args;
            directive_match = re.match(r"^(\w[\w.-]*)\s+(.*?)\s*;", stripped)
            if directive_match:
                name = directive_match.group(1)
                args = directive_match.group(2).strip()
                self.directives.append(NginxDirective(
                    name=name,
                    args=args,
                    line=line_num,
                    block_context=current_context,
                ))

        logger.debug(f"Parsed {len(self.directives)} directives from {filepath}")
        return self.directives

    def get_directive(self, name: str) -> list[NginxDirective]:
        """Get all directives with a given name."""
        return [d for d in self.directives if d.name == name]

    def has_directive(self, name: str) -> bool:
        """Check if a directive exists."""
        return any(d.name == name for d in self.directives)

    def get_directive_value(self, name: str) -> str | None:
        """Get the first value for a directive."""
        for d in self.directives:
            if d.name == name:
                return d.args
        return None
