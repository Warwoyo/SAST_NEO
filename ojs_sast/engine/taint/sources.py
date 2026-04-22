"""Taint source definitions for OJS-SAST.

Taint sources are data entry points from untrusted user input.
Any variable receiving data from these sources is marked as tainted.
"""

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
ALL_SOURCE_IDENTIFIERS = (
    SUPERGLOBALS | OJS_REQUEST_METHODS | DATABASE_READS | FILE_READS | ENV_VARS
)


def is_taint_source(text: str) -> bool:
    """Check if the given text represents a taint source.

    Args:
        text: AST node text or function/variable name.

    Returns:
        True if the text matches a known taint source.
    """
    # Direct match against superglobals
    for sg in SUPERGLOBALS:
        if sg in text:
            return True

    # Check OJS request methods
    for method in OJS_REQUEST_METHODS:
        if method in text:
            return True

    # Check file reads
    for func in FILE_READS:
        if func in text:
            return True

    # Check env vars
    for ev in ENV_VARS:
        if ev in text:
            return True

    return False


def get_source_category(text: str) -> str | None:
    """Determine the category of a taint source.

    Returns:
        Category name or None if not a source.
    """
    for sg in SUPERGLOBALS:
        if sg in text:
            return "superglobals"
    for method in OJS_REQUEST_METHODS:
        if method in text:
            return "ojs_request"
    for func in DATABASE_READS:
        if func in text:
            return "database_reads"
    for func in FILE_READS:
        if func in text:
            return "file_reads"
    for ev in ENV_VARS:
        if ev in text:
            return "env_vars"
    return None
