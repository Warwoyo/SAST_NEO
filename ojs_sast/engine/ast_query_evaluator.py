"""Tree-sitter AST Query Evaluator for OJS-SAST.

Executes tree-sitter S-expression queries from YAML rules against PHP ASTs.
Handles predicates that the Python binding does NOT evaluate natively:
  - #match?     — regex must match against captured node text
  - #not-match? — regex must NOT match against captured node text
  - #eq?        — handled natively by tree-sitter (no extra work needed)
"""

import re
from dataclasses import dataclass, field
from typing import Any

from ojs_sast.utils.logger import logger


@dataclass
class ASTMatch:
    """Result of a single AST query match."""
    pattern_index: int
    captures: dict[str, list[Any]]  # capture_name -> list of nodes
    line: int = 0                   # 1-indexed line of the primary match
    text: str = ""                  # source text of the primary matched node


# ──────────────────────────────────────────────────────────────────────────────
# Predicate extraction
# ──────────────────────────────────────────────────────────────────────────────

# Matches:  (#match? @body "payment|manager")
#           (#not-match? @body "FormValidatorCSRF")
_PREDICATE_RE = re.compile(
    r'\(\s*#(match\?|not-match\?)\s+@(\w+)\s+"([^"]+)"\s*\)'
)


@dataclass
class _Predicate:
    """A parsed #match? or #not-match? predicate."""
    kind: str          # "match?" or "not-match?"
    capture_name: str  # e.g. "body"
    pattern: re.Pattern


def _extract_predicates(query_string: str) -> list[_Predicate]:
    """Extract #match? and #not-match? predicates from a query string.

    These predicates are NOT evaluated by the tree-sitter Python binding;
    we must apply them manually as a post-filter on match results.
    """
    predicates = []
    for m in _PREDICATE_RE.finditer(query_string):
        kind = m.group(1)
        capture = m.group(2)
        regex_str = m.group(3)
        try:
            compiled = re.compile(regex_str)
        except re.error as e:
            logger.warning(f"Invalid predicate regex '{regex_str}': {e}")
            continue
        predicates.append(_Predicate(kind=kind, capture_name=capture, pattern=compiled))
    return predicates


def _strip_custom_predicates(query_string: str) -> str:
    """Remove #match? and #not-match? predicates from the query string.

    tree-sitter will raise an error or silently ignore these predicates,
    so we strip them and handle them in Python post-filtering.
    We keep #eq? because tree-sitter handles that natively.
    """
    return _PREDICATE_RE.sub("", query_string)


# ──────────────────────────────────────────────────────────────────────────────
# Core evaluator
# ──────────────────────────────────────────────────────────────────────────────

def evaluate_ast_query(
    query_string: str,
    tree: Any,
    source_bytes: bytes,
    language: Any,
) -> list[ASTMatch]:
    """Execute a tree-sitter query against a PHP AST and return matches.

    Args:
        query_string: A tree-sitter S-expression query (from YAML rule).
        tree: A tree-sitter Tree object (parsed PHP file).
        source_bytes: The raw source code bytes.
        language: The tree-sitter Language object (PHP).

    Returns:
        List of ASTMatch results. Empty list if no matches or query is invalid.
    """
    from tree_sitter import Query, QueryCursor

    # 1. Extract custom predicates we need to evaluate manually
    predicates = _extract_predicates(query_string)

    # 2. Strip them from the query so tree-sitter doesn't choke
    clean_query = _strip_custom_predicates(query_string).strip()

    if not clean_query:
        return []

    # 3. Compile the query
    try:
        query = Query(language, clean_query)
    except Exception as e:
        logger.debug(f"AST query compilation failed: {e}\nQuery: {clean_query[:200]}")
        return []

    # 4. Execute
    cursor = QueryCursor(query)
    try:
        raw_matches = cursor.matches(tree.root_node)
    except Exception as e:
        logger.debug(f"AST query execution failed: {e}")
        return []

    # 5. Post-filter with custom predicates
    results: list[ASTMatch] = []
    for pattern_index, captures in raw_matches:
        if not _apply_predicates(predicates, captures, source_bytes):
            continue

        # Determine the primary node for line reporting.
        # Priority: first named capture that isn't a single-char internal name.
        primary_node = _pick_primary_node(captures)

        line = (primary_node.start_point[0] + 1) if primary_node else 0
        text = ""
        if primary_node:
            text = source_bytes[primary_node.start_byte:primary_node.end_byte].decode(
                "utf-8", errors="replace"
            )

        results.append(ASTMatch(
            pattern_index=pattern_index,
            captures=captures,
            line=line,
            text=text,
        ))

    return results


def _apply_predicates(
    predicates: list[_Predicate],
    captures: dict[str, list[Any]],
    source_bytes: bytes,
) -> bool:
    """Apply manual predicates to a single match. Returns True if all pass."""
    for pred in predicates:
        nodes = captures.get(pred.capture_name, [])
        if not nodes:
            # Capture not found → treat as failed for #match?, passed for #not-match?
            if pred.kind == "match?":
                return False
            continue

        # Concatenate text from all nodes in the capture
        text = " ".join(
            source_bytes[n.start_byte:n.end_byte].decode("utf-8", errors="replace")
            for n in nodes
        )

        if pred.kind == "match?":
            if not pred.pattern.search(text):
                return False
        elif pred.kind == "not-match?":
            if pred.pattern.search(text):
                return False

    return True


def _pick_primary_node(captures: dict[str, list[Any]]) -> Any | None:
    """Pick the most meaningful captured node for line-number reporting.

    Prefers captures named 'method', 'fn', 'sink', 'scope', 'prop',
    then falls back to the first capture with the shortest name.
    """
    priority_names = ("method", "fn", "sink", "scope", "prop")
    for name in priority_names:
        nodes = captures.get(name)
        if nodes:
            return nodes[0]

    # Fallback: first capture by shortest name
    for name in sorted(captures.keys(), key=len):
        nodes = captures.get(name)
        if nodes:
            return nodes[0]

    return None
