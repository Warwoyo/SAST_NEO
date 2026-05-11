"""Sanitizer definitions for OJS-SAST.

Sanitizers are functions that clean or validate tainted data,
removing or neutralizing the taint.
"""

import re

SANITIZERS: dict[str, frozenset[str]] = {
    "sql": frozenset([
        "escapeString", "quote", "mysqli_real_escape_string",
        "mysql_real_escape_string", "mysql_escape_string",
        "intval", "floatval", "is_numeric",
        "prepare", "bindParam", "bindValue",
    ]),
    "xss": frozenset([
        "htmlspecialchars", "htmlentities", "strip_tags",
        "stripUnsafeHtml", "getHtmlPurifier",
        "xss_clean", "ENT_QUOTES",
        "PKPString::stripUnsafeHtml",
    ]),
    "path": frozenset([
        "basename", "realpath", "validatePath",
    ]),
    "command": frozenset([
        "escapeshellarg", "escapeshellcmd",
    ]),
    "url": frozenset([
        "filter_var", "parse_url",
    ]),
    "general": frozenset([
        "filter_var", "filter_input", "preg_replace",
        "ctype_alpha", "ctype_digit", "ctype_alnum",
        "is_int", "is_string", "is_array",
        "(int)", "(integer)", "(bool)", "(boolean)", "(float)", "(double)", "(real)",
        "PKPString::strtoupper", "urldecode", "iconv"
    ]),
}


def _build_sanitizer_regex(func: str) -> re.Pattern:
    """Build a compiled regex for a sanitizer identifier.

    - Type casts like (int): match with optional whitespace inside parens.
    - Class methods like PKPString::strtoupper: match with optional whitespace
      around ::.
    - Standard functions: must NOT be preceded by $ or ->, and must be
      followed by an opening parenthesis.
    """
    if func.startswith("(") and func.endswith(")"):
        # Type cast: "(int)" -> r"\(\s*int\s*\)"
        inner = func[1:-1]
        return re.compile(rf"\(\s*{re.escape(inner)}\s*\)")
    elif "::" in func:
        # Class method: "PKPString::strtoupper" -> r"\bPKPString\s*::\s*strtoupper\b"
        parts = func.split("::", 1)
        return re.compile(
            rf"\b{re.escape(parts[0])}\s*::\s*{re.escape(parts[1])}\b"
        )
    else:
        # Require: not preceded by $ or ->, and followed by (
        return re.compile(rf"(?<!\$)(?<!->)\b{re.escape(func)}\s*\(")


# Pre-compile regexes: list of (func_name, category, compiled_pattern)
_SANITIZER_REGEXES: list[tuple[str, str, re.Pattern]] = []
for _category, _funcs in SANITIZERS.items():
    for _func in _funcs:
        _SANITIZER_REGEXES.append((_func, _category, _build_sanitizer_regex(_func)))

# Flat set for quick lookup (still useful for debugging / introspection)
_ALL_SANITIZERS: frozenset[str] = frozenset().union(*SANITIZERS.values())


def is_sanitizer(text: str) -> bool:
    """Check if the given text represents a sanitizer."""
    for _func, _cat, pattern in _SANITIZER_REGEXES:
        if pattern.search(text):
            return True
    return False


def get_sanitizer_category(text: str) -> str | None:
    """Get the sanitizer category for the given text."""
    for _func, category, pattern in _SANITIZER_REGEXES:
        if pattern.search(text):
            return category
    return None


def is_effective_sanitizer(sanitizer_text: str, sink_category: str) -> bool:
    """Check if a sanitizer is effective against a specific sink category.

    For example, htmlspecialchars() sanitizes XSS but NOT SQL injection.
    """
    mapping = {
        "sql_injection": "sql",
        "xss": "xss",
        "file_ops": "path",
        "rce": "command",
        "ssrf": "url",
        "xxe": None,
        "deserialization": None,
        "header_injection": "general",
        "ldap": "general",
    }
    required_cat = mapping.get(sink_category)
    if required_cat is None:
        return False

    san_cat = get_sanitizer_category(sanitizer_text)
    return san_cat == required_cat or san_cat == "general"
