"""Smarty template (.tpl) security scanner for OJS-SAST.

Detects common XSS patterns in Smarty templates:
- Unescaped variables in HTML attributes
- Unescaped translation variables
- Missing strip_unsafe_html before nl2br
"""

import re
from dataclasses import dataclass

# Pattern 1: Unescaped variables in HTML attributes
# Matches: value="{$someVar}" but NOT value="{$someVar|escape}"
_UNESCAPED_ATTR_RE = re.compile(
    r"""value\s*=\s*["']\{\$[a-zA-Z0-9_]+(?!\|escape)\}["']""",
)

# Pattern 2: Unescaped translation variables
# Matches: {translate key="..." name=$var} without |escape
_UNESCAPED_TRANSLATE_RE = re.compile(
    r"""\{translate[^}]+name=\$[a-zA-Z0-9_]+(?:\(\))?(?!\|escape)[^}]*\}""",
)

# Pattern 3: nl2br without strip_unsafe_html
# Matches: {$someVar|nl2br} but NOT {$someVar|strip_unsafe_html|nl2br}
_UNSTRIPPED_NL2BR_RE = re.compile(
    r"""\{\$[a-zA-Z0-9_]+\|nl2br\}""",
)


@dataclass
class SmartyFinding:
    """A security finding from Smarty template scanning."""
    pattern_name: str
    line_number: int
    matched_text: str
    description: str
    cwe: str


def scan_smarty_template(content: str) -> list[SmartyFinding]:
    """Scan Smarty template content for XSS vulnerabilities.

    Args:
        content: The raw text content of a .tpl file.

    Returns:
        List of SmartyFinding objects.
    """
    findings: list[SmartyFinding] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Skip Smarty comments
        if stripped.startswith("{*") or stripped.startswith("*"):
            continue

        # Pattern 1: Unescaped attribute
        for match in _UNESCAPED_ATTR_RE.finditer(line):
            findings.append(SmartyFinding(
                pattern_name="unescaped_attribute",
                line_number=i,
                matched_text=match.group(0),
                description=(
                    "Smarty variable in HTML attribute without |escape modifier. "
                    "This may lead to Reflected or Stored XSS."
                ),
                cwe="CWE-79",
            ))

        # Pattern 2: Unescaped translate
        for match in _UNESCAPED_TRANSLATE_RE.finditer(line):
            findings.append(SmartyFinding(
                pattern_name="unescaped_translate",
                line_number=i,
                matched_text=match.group(0),
                description=(
                    "Smarty {translate} tag passes a variable without |escape. "
                    "User-controlled translation parameters can inject HTML/JS."
                ),
                cwe="CWE-79",
            ))

        # Pattern 3: nl2br without strip
        for match in _UNSTRIPPED_NL2BR_RE.finditer(line):
            findings.append(SmartyFinding(
                pattern_name="nl2br_without_strip",
                line_number=i,
                matched_text=match.group(0),
                description=(
                    "Smarty variable uses |nl2br without |strip_unsafe_html. "
                    "HTML in the variable will be rendered, enabling Stored XSS."
                ),
                cwe="CWE-79",
            ))

    return findings
