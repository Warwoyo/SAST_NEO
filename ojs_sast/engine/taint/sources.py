"""Taint source definitions for OJS-SAST.

Taint sources are data entry points from untrusted user input.
Any variable receiving data from these sources is marked as tainted.
"""

import re

# PHP superglobals that contain user-controlled data
SUPERGLOBALS = frozenset([
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
    "$_FILES", "$_SERVER",
])

# OJS-specific request methods that read user input
OJS_REQUEST_METHODS = frozenset([
    "getUserVar",
    "getQueryString",
    "getQueryArray",
])

# OJS request class names
OJS_REQUEST_CLASSES = frozenset([
    "Request",
    "PKPRequest",
])

# Database read functions (data from DB is second-order taint)
DATABASE_READS = frozenset([
    "DAOResultFactory",
    "getById",
    "retrieve",
])

# File read functions
FILE_READS = frozenset([
    "file_get_contents",
    "fread",
    "fgets",
    "fgetcsv",
    "file",
    "readfile",
])

# Environment variable access
ENV_VARS = frozenset([
    "getenv",
    "$_ENV",
])

# Complete mapping by category
TAINT_SOURCES: dict[str, frozenset[str]] = {
    "superglobals": SUPERGLOBALS,
    "ojs_request": OJS_REQUEST_METHODS,
    "database_reads": DATABASE_READS,
    "file_reads": FILE_READS,
    "env_vars": ENV_VARS,
}

# Flat set of all source identifiers for quick lookup
# NOTE: DATABASE_READS excluded — DB output is not first-order user input.
ALL_SOURCE_IDENTIFIERS = (
    SUPERGLOBALS | OJS_REQUEST_METHODS | FILE_READS | ENV_VARS
)

# --- Compiled Regexes for precise matching ---
_STRING_LITERAL_RE = re.compile(
    r"^\s*['\"]"    # starts with a quote (single or double)
    r"|^\s*<<<"      # heredoc / nowdoc
)


def _build_source_regex(identifier: str) -> re.Pattern:
    """Build a compiled regex for a source identifier.

    - Superglobals ($-prefixed): use a negative lookbehind so that
      e.g. $_GET doesn't match inside $my_GET_value.
    - Standard functions/methods: must NOT be preceded by $ or ->,
      and must be followed by an opening parenthesis.
    """
    if identifier.startswith("$"):
        # Escape the $ and bracket chars, use lookbehind for safety
        escaped = re.escape(identifier)
        return re.compile(rf"(?<![a-zA-Z0-9_]){escaped}\b")
    else:
        # Require: not preceded by $ or ->, and followed by (
        return re.compile(rf"(?<!\$)(?<!->)\b{re.escape(identifier)}\s*\(")


# Pre-compile regexes per category for is_taint_source / get_source_category
_SOURCE_REGEXES: dict[str, list[tuple[str, re.Pattern]]] = {}
for _cat_name, _identifiers in {
    "superglobals": SUPERGLOBALS,
    "ojs_request": OJS_REQUEST_METHODS,
    "file_reads": FILE_READS,
    "env_vars": ENV_VARS,
}.items():
    _SOURCE_REGEXES[_cat_name] = [
        (ident, _build_source_regex(ident)) for ident in _identifiers
    ]

# Also compile DATABASE_READS for get_source_category (but NOT for is_taint_source)
_DB_READ_REGEXES: list[tuple[str, re.Pattern]] = [
    (ident, _build_source_regex(ident)) for ident in DATABASE_READS
]


def is_taint_source(text: str) -> bool:
    """Check if the given text represents a taint source.

    Args:
        text: AST node text or function/variable name.

    Returns:
        True if the text matches a known taint source.
    """
    # Exclude hardcoded string literals — they are not user-controlled.
    if _STRING_LITERAL_RE.match(text):
        return False

    for _cat, pairs in _SOURCE_REGEXES.items():
        for _ident, pattern in pairs:
            if pattern.search(text):
                return True

    return False


def get_source_category(text: str) -> str | None:
    """Determine the category of a taint source.

    Returns:
        Category name or None if not a source.
    """
    for cat, pairs in _SOURCE_REGEXES.items():
        for _ident, pattern in pairs:
            if pattern.search(text):
                return cat

    # Also check DATABASE_READS for categorization purposes
    for _ident, pattern in _DB_READ_REGEXES:
        if pattern.search(text):
            return "database_reads"

    return None
