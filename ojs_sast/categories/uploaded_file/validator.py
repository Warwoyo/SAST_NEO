"""File extension and MIME type validator for uploaded files."""

import os

from ojs_sast.utils.logger import logger

# Dangerous file extensions that can execute code on the server
DANGEROUS_EXTENSIONS = {
    "critical": {
        ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps",
        ".phar", ".cgi", ".pl", ".py", ".rb", ".sh", ".bash",
        ".jsp", ".jspx", ".asp", ".aspx", ".ashx",
    },
    "high": {
        ".htaccess", ".htpasswd", ".ini", ".env",
        ".config", ".conf", ".yml", ".yaml",
        ".exe", ".dll", ".so", ".bat", ".cmd", ".com", ".scr",
    },
    "medium": {
        ".js", ".svg", ".html", ".htm", ".xhtml",
        ".shtml", ".shtm",
    },
}

# Allowed extensions per upload context
ALLOWED_EXTENSIONS_BY_CONTEXT = {
    "submission_file": {
        ".pdf", ".doc", ".docx", ".odt", ".rtf", ".tex",
        ".epub", ".xml", ".html",
    },
    "galley": {
        ".pdf", ".html", ".htm", ".xml", ".epub",
    },
    "cover_image": {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff",
    },
    "supplementary": {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv",
        ".zip", ".tar", ".gz",
        ".mp3", ".mp4", ".avi", ".mov",
        ".jpg", ".jpeg", ".png", ".gif",
    },
    "plugin_zip": {
        ".tar", ".gz", ".zip",
    },
    "default": {
        ".pdf", ".doc", ".docx", ".odt", ".rtf",
        ".jpg", ".jpeg", ".png", ".gif",
        ".xml", ".csv", ".zip",
    },
}

# All dangerous extensions flattened
ALL_DANGEROUS = set()
for _exts in DANGEROUS_EXTENSIONS.values():
    ALL_DANGEROUS |= _exts


def get_extension(filepath: str) -> str:
    """Get the lowercase file extension."""
    return os.path.splitext(filepath)[1].lower()


def is_dangerous_extension(filepath: str) -> tuple[bool, str]:
    """Check if a file has a dangerous extension.

    Returns:
        Tuple of (is_dangerous, risk_level).
    """
    ext = get_extension(filepath)

    for level in ("critical", "high", "medium"):
        if ext in DANGEROUS_EXTENSIONS[level]:
            return True, level

    return False, "none"


def is_allowed_extension(filepath: str, context: str = "default") -> bool:
    """Check if a file extension is allowed for the given upload context.

    Args:
        filepath: File path to check.
        context: Upload context (submission_file, galley, etc.).

    Returns:
        True if the extension is allowed.
    """
    ext = get_extension(filepath)
    allowed = ALLOWED_EXTENSIONS_BY_CONTEXT.get(context, ALLOWED_EXTENSIONS_BY_CONTEXT["default"])
    return ext in allowed


def is_double_extension(filepath: str) -> bool:
    """Check for double extensions that might bypass filters.

    Examples: file.php.jpg, file.phtml.png

    Returns:
        True if a dangerous extension is hidden in a double extension.
    """
    basename = os.path.basename(filepath)
    parts = basename.split(".")

    if len(parts) < 3:
        return False

    # Check each internal extension
    for part in parts[1:-1]:
        ext = f".{part.lower()}"
        if ext in ALL_DANGEROUS:
            return True

    return False


def get_risk_level(filepath: str) -> str:
    """Get the risk level for a file based on its extension.

    Returns:
        'critical', 'high', 'medium', 'low', or 'safe'.
    """
    is_dangerous, level = is_dangerous_extension(filepath)
    if is_dangerous:
        return level

    if is_double_extension(filepath):
        return "high"

    return "safe"
