"""Sanitizer definitions for OJS-SAST.

Sanitizers are functions that clean or validate tainted data,
removing or neutralizing the taint.
"""

SANITIZERS: dict[str, frozenset[str]] = {
    "sql": frozenset([
        "escapeString", "quote", "mysqli_real_escape_string",
        "intval", "floatval", "is_numeric",
        "prepare", "bindParam", "bindValue",
    ]),
    "xss": frozenset([
        "htmlspecialchars", "htmlentities", "strip_tags",
        "stripUnsafeHtml", "getHtmlPurifier",
        "xss_clean", "ENT_QUOTES",
    ]),
    "path": frozenset([
        "basename", "realpath", "validatePath",
    ]),
    "general": frozenset([
        "filter_var", "filter_input", "preg_replace",
        "ctype_alpha", "ctype_digit", "ctype_alnum",
        "is_int", "is_string", "is_array",
        "(int)", "(integer)", "(bool)", "(boolean)", "(float)", "(double)", "(real)",
        "PKPString::strtoupper", "urldecode", "iconv"
    ]),
}

# Flat set for quick lookup
_ALL_SANITIZERS: frozenset[str] = frozenset().union(*SANITIZERS.values())


def is_sanitizer(text: str) -> bool:
    """Check if the given text represents a sanitizer."""
    for s in _ALL_SANITIZERS:
        if s in text:
            return True
    return False


def get_sanitizer_category(text: str) -> str | None:
    """Get the sanitizer category for the given text."""
    for category, funcs in SANITIZERS.items():
        for func in funcs:
            if func in text:
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
        "rce": None,  # No simple sanitizer for RCE
        "ssrf": "path",
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
