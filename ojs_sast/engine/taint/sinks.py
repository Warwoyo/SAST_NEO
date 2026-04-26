"""Taint sink definitions for OJS-SAST."""
import re

TAINT_SINKS: dict[str, frozenset[str]] = {
    "sql_injection": frozenset([
        "query", "retrieve", "update", "mysql_query",
        "mysqli_query", "pg_query", "execute",
    ]),
    "xss": frozenset([
        "echo", "print", "printf",
    ]),
    "rce": frozenset([
        "exec", "shell_exec", "system", "passthru",
        "popen", "proc_open", "eval",
        "create_function",
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
# Menyimpan pattern regex yang sudah di-compile agar performa SAST tetap cepat
_SINK_REGEXES: dict[str, re.Pattern] = {}

for _category, _funcs in TAINT_SINKS.items():
    for _func in _funcs:
        _SINK_LOOKUP.setdefault(_func, []).append(_category)
        if _func not in _SINK_REGEXES:
            # \b memastikan hanya kata utuh yang cocok.
            # Contoh: \bexec\b tidak akan cocok dengan "execute" atau "curl_exec"
            _SINK_REGEXES[_func] = re.compile(rf'\b{re.escape(_func)}\b')


def is_taint_sink(text: str) -> bool:
    """Check if the given text represents a taint sink using word boundaries."""
    for func_name, pattern in _SINK_REGEXES.items():
        if pattern.search(text):
            return True
    return False


def get_sink_categories(text: str) -> list[str]:
    """Get the vulnerability categories for a sink using word boundaries.

    Returns:
        List of category names (e.g., ['sql_injection', 'ssrf']).
    """
    categories: set[str] = set() # Menggunakan set() untuk otomatis mencegah duplikasi
    for func_name, pattern in _SINK_REGEXES.items():
        if pattern.search(text):
            categories.update(_SINK_LOOKUP[func_name])
            
    return list(categories)