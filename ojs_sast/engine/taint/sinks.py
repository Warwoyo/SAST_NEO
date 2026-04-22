"""Taint sink definitions for OJS-SAST.

Sinks are dangerous functions/operations that must not receive
tainted data without proper sanitization.
"""

TAINT_SINKS: dict[str, frozenset[str]] = {
    "sql_injection": frozenset([
        "query", "retrieve", "update", "mysql_query",
        "mysqli_query", "pg_query", "execute",
    ]),
    "xss": frozenset([
        "echo", "print", "printf", "assign",
        "display", "fetch",
    ]),
    "rce": frozenset([
        "exec", "shell_exec", "system", "passthru",
        "popen", "proc_open", "eval", "assert",
        "preg_replace", "create_function",
    ]),
    "file_ops": frozenset([
        "include", "include_once", "require", "require_once",
        "file_get_contents", "fopen", "unlink", "rename",
        "move_uploaded_file", "copy", "readfile",
    ]),
    "ssrf": frozenset([
        "curl_exec", "curl_init", "file_get_contents",
        "fsockopen", "fopen",
    ]),
    "xxe": frozenset([
        "simplexml_load_string", "simplexml_load_file",
        "DOMDocument", "XMLReader",
    ]),
    "deserialization": frozenset([
        "unserialize", "yaml_parse", "json_decode",
    ]),
    "header_injection": frozenset([
        "header", "setcookie",
    ]),
    "ldap": frozenset([
        "ldap_search", "ldap_bind",
    ]),
}

# Build flat lookup: function_name -> list of sink categories
_SINK_LOOKUP: dict[str, list[str]] = {}
for _category, _funcs in TAINT_SINKS.items():
    for _func in _funcs:
        _SINK_LOOKUP.setdefault(_func, []).append(_category)


def is_taint_sink(text: str) -> bool:
    """Check if the given text represents a taint sink."""
    for func_name in _SINK_LOOKUP:
        if func_name in text:
            return True
    return False


def get_sink_categories(text: str) -> list[str]:
    """Get the vulnerability categories for a sink.

    Returns:
        List of category names (e.g., ['sql_injection', 'ssrf']).
    """
    categories: list[str] = []
    for func_name, cats in _SINK_LOOKUP.items():
        if func_name in text:
            categories.extend(cats)
    return list(set(categories))
