"""Apache configuration and .htaccess parser."""

import re
from dataclasses import dataclass

from ojs_sast.utils.file_utils import read_file_safe
from ojs_sast.utils.logger import logger


@dataclass
class ApacheDirective:
    """A parsed Apache directive."""
    name: str
    args: str
    line: int
    block_context: str = ""


class ApacheConfigParser:
    """Parser for Apache configuration and .htaccess files."""

    def __init__(self) -> None:
        self.directives: list[ApacheDirective] = []
        self.raw_content: str = ""
        self.filepath: str = ""

    def parse(self, filepath: str) -> list[ApacheDirective]:
        """Parse an Apache configuration file.

        Args:
            filepath: Path to the Apache config or .htaccess file.

        Returns:
            List of parsed directives.
        """
        self.filepath = filepath
        content = read_file_safe(filepath)
        if not content:
            logger.warning(f"Cannot read Apache config: {filepath}")
            return []

        self.raw_content = content
        self.directives = []

        context_stack: list[str] = []
        current_context = "main"

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            # Opening block tag: <Directory "/path">
            block_open = re.match(r"^<(\w+)\s*(.*?)>", stripped)
            if block_open and not stripped.startswith("</"):
                context_stack.append(current_context)
                block_type = block_open.group(1)
                block_args = block_open.group(2).strip()
                current_context = f"{block_type} {block_args}".strip()
                self.directives.append(ApacheDirective(
                    name=block_type,
                    args=block_args,
                    line=line_num,
                    block_context=current_context,
                ))
                continue

            # Closing block tag: </Directory>
            block_close = re.match(r"^</(\w+)>", stripped)
            if block_close:
                if context_stack:
                    current_context = context_stack.pop()
                continue

            # Regular directive: Name args
            directive_match = re.match(r"^(\w+)\s+(.*)", stripped)
            if directive_match:
                name = directive_match.group(1)
                args = directive_match.group(2).strip()
                self.directives.append(ApacheDirective(
                    name=name,
                    args=args,
                    line=line_num,
                    block_context=current_context,
                ))
            elif re.match(r"^(\w+)\s*$", stripped):
                # Directive with no args (e.g., "RewriteEngine")
                self.directives.append(ApacheDirective(
                    name=stripped,
                    args="",
                    line=line_num,
                    block_context=current_context,
                ))

        logger.debug(f"Parsed {len(self.directives)} directives from {filepath}")
        return self.directives

    def get_directive(self, name: str) -> list[ApacheDirective]:
        """Get all directives with a given name (case-insensitive)."""
        name_lower = name.lower()
        return [d for d in self.directives if d.name.lower() == name_lower]

    def has_directive(self, name: str) -> bool:
        """Check if a directive exists (case-insensitive)."""
        name_lower = name.lower()
        return any(d.name.lower() == name_lower for d in self.directives)

    def get_directive_value(self, name: str) -> str | None:
        """Get the first value for a directive."""
        name_lower = name.lower()
        for d in self.directives:
            if d.name.lower() == name_lower:
                return d.args
        return None
