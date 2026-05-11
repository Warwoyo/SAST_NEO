"""PHP parser using tree-sitter for AST generation."""

from typing import Any

from ojs_sast.utils.logger import logger

# Lazy-loaded parser instance
_parser = None
_php_language = None


def _init_parser() -> None:
    """Initialize the tree-sitter parser with PHP grammar."""
    global _parser, _php_language

    if _parser is not None:
        return

    try:
        import tree_sitter_php as tsphp
        from tree_sitter import Language, Parser

        _php_language = Language(tsphp.language_php())
        _parser = Parser(_php_language)
        logger.debug("tree-sitter PHP parser initialized successfully")
    except ImportError as e:
        logger.error(
            f"Failed to import tree-sitter dependencies: {e}. "
            "Install with: pip install tree-sitter tree-sitter-php"
        )
        raise
    except Exception as e:
        logger.error(f"Failed to initialize tree-sitter parser: {e}")
        raise


def parse_php(source_code: str | bytes) -> Any | None:
    """Parse PHP source code into an AST.

    Args:
        source_code: PHP source code as string or bytes.

    Returns:
        tree-sitter Tree object, or None if parsing fails.
    """
    _init_parser()

    if _parser is None:
        return None

    if isinstance(source_code, str):
        source_code = source_code.encode("utf-8")

    try:
        tree = _parser.parse(source_code)
        return tree
    except Exception as e:
        logger.warning(f"Failed to parse PHP code: {e}")
        return None


def parse_php_file(filepath: str) -> tuple[Any | None, bytes]:
    """Parse a PHP file into an AST.

    Args:
        filepath: Path to the PHP file.

    Returns:
        Tuple of (tree-sitter Tree or None, source bytes).
    """
    try:
        with open(filepath, "rb") as f:
            source_bytes = f.read()
    except (OSError, PermissionError) as e:
        logger.warning(f"Cannot read PHP file {filepath}: {e}")
        return None, b""

    tree = parse_php(source_bytes)
    return tree, source_bytes


def get_php_language():
    """Return the tree-sitter PHP Language object.

    Initializes the parser lazily if needed.

    Returns:
        tree_sitter.Language for PHP, or None if init fails.
    """
    _init_parser()
    return _php_language
