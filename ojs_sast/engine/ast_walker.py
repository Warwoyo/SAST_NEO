"""AST traversal helpers for tree-sitter nodes."""

from collections.abc import Generator
from typing import Any


def walk_tree(node: Any) -> Generator[Any, None, None]:
    """Depth-first traversal of a tree-sitter AST node.

    Args:
        node: A tree-sitter Node.

    Yields:
        Each node in depth-first order.
    """
    yield node
    for child in node.children:
        yield from walk_tree(child)


def find_nodes_by_type(node: Any, type_name: str) -> list[Any]:
    """Find all descendant nodes of a specific type.

    Args:
        node: Root tree-sitter Node.
        type_name: The node type to search for.

    Returns:
        List of matching nodes.
    """
    return [n for n in walk_tree(node) if n.type == type_name]


def find_nodes_by_types(node: Any, type_names: set[str]) -> list[Any]:
    """Find all descendant nodes matching any of the given types."""
    return [n for n in walk_tree(node) if n.type in type_names]


def get_node_text(node: Any, source_bytes: bytes) -> str:
    """Extract the source text for a tree-sitter node.

    Args:
        node: A tree-sitter Node.
        source_bytes: The source code as bytes.

    Returns:
        The text content of the node.
    """
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def get_line_number(node: Any) -> int:
    """Get the 1-indexed line number for a tree-sitter node."""
    return node.start_point[0] + 1


def get_end_line(node: Any) -> int:
    """Get the 1-indexed end line number for a tree-sitter node."""
    return node.end_point[0] + 1


def get_function_name(node: Any, source_bytes: bytes) -> str | None:
    """Extract the function name from a function call node.

    Handles both simple calls like func() and method calls like $obj->method().

    Args:
        node: A function_call_expression or member_call_expression node.
        source_bytes: Source code bytes.

    Returns:
        The function/method name, or None if not determinable.
    """
    if node.type == "function_call_expression":
        func_node = node.child_by_field_name("function")
        if func_node:
            return get_node_text(func_node, source_bytes)

    elif node.type == "member_call_expression":
        name_node = node.child_by_field_name("name")
        if name_node:
            return get_node_text(name_node, source_bytes)

    elif node.type == "scoped_call_expression":
        name_node = node.child_by_field_name("name")
        if name_node:
            return get_node_text(name_node, source_bytes)

    return None


def get_assignment_target(node: Any, source_bytes: bytes) -> str | None:
    """Extract the variable name from an assignment expression.

    Args:
        node: An assignment_expression node.
        source_bytes: Source code bytes.

    Returns:
        The variable name (e.g., '$var'), or None.
    """
    left = node.child_by_field_name("left")
    if left:
        return get_node_text(left, source_bytes)
    return None


def get_assignment_value(node: Any, source_bytes: bytes) -> str | None:
    """Extract the value expression from an assignment.

    Args:
        node: An assignment_expression node.
        source_bytes: Source code bytes.

    Returns:
        The right-hand side expression text.
    """
    right = node.child_by_field_name("right")
    if right:
        return get_node_text(right, source_bytes)
    return None


def find_variables_in_node(node: Any, source_bytes: bytes) -> list[str]:
    """Find all variable references within a node.

    Args:
        node: A tree-sitter Node.
        source_bytes: Source code bytes.

    Returns:
        List of variable names (e.g., ['$var1', '$var2']).
    """
    variables = []
    for n in walk_tree(node):
        if n.type == "variable_name":
            var_text = get_node_text(n, source_bytes)
            if not var_text.startswith("$"):
                var_text = "$" + var_text
            variables.append(var_text)
    return variables


def get_function_arguments(node: Any, source_bytes: bytes) -> list[str]:
    """Extract argument texts from a function call node.

    Args:
        node: A function/method call expression node.
        source_bytes: Source code bytes.

    Returns:
        List of argument text strings.
    """
    args_node = node.child_by_field_name("arguments")
    if not args_node:
        return []

    arguments = []
    for child in args_node.children:
        if child.type == "argument":
            arguments.append(get_node_text(child, source_bytes))
        elif child.type not in ("(", ")", ","):
            arguments.append(get_node_text(child, source_bytes))
    return arguments
