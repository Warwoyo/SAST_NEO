"""File system utilities for OJS-SAST."""

import os
from collections.abc import Generator

from ojs_sast.utils.logger import logger

# Directories to always exclude when scanning OJS installations
DEFAULT_EXCLUDE_DIRS = {
    "cache",
    "lib/vendor",
    "node_modules",
    ".git",
    "__pycache__",
    ".svn",
    "tests",
    "tools",
    "lib/pkp/tests",
    "lib/pkp/tools",
}


def find_files(
    directory: str,
    extensions: set[str] | None = None,
    exclude_dirs: set[str] | None = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10 MB
) -> Generator[str, None, None]:
    """Recursively find files matching the given extensions.

    Args:
        directory: Root directory to search.
        extensions: Set of extensions to include (e.g., {".php", ".js"}).
                   If None, yields all files.
        exclude_dirs: Directory names/paths to skip.
        max_file_size: Maximum file size in bytes to include.

    Yields:
        Absolute paths to matching files.
    """
    if exclude_dirs is None:
        exclude_dirs = DEFAULT_EXCLUDE_DIRS

    directory = os.path.abspath(directory)

    for root, dirs, files in os.walk(directory, topdown=True):
        # Compute relative path from base directory for exclusion matching
        rel_root = os.path.relpath(root, directory)

        # Filter out excluded directories in-place to prevent os.walk from descending
        dirs[:] = [
            d for d in dirs
            if d not in exclude_dirs
            and os.path.join(rel_root, d).replace("\\", "/") not in exclude_dirs
            and not d.startswith(".")
        ]

        for filename in files:
            filepath = os.path.join(root, filename)

            # Check extension
            if extensions:
                _, ext = os.path.splitext(filename)
                if ext.lower() not in extensions:
                    continue

            # Check file size
            try:
                file_size = os.path.getsize(filepath)
                if file_size > max_file_size:
                    logger.debug(f"Skipping large file ({file_size} bytes): {filepath}")
                    continue
                if file_size == 0:
                    continue
            except OSError:
                continue

            yield filepath


def read_file_safe(filepath: str, encoding: str = "utf-8") -> str | None:
    """Read a file's content with error handling.

    Args:
        filepath: Path to the file.
        encoding: Text encoding to use.

    Returns:
        File content as string, or None if reading fails.
    """
    try:
        with open(filepath, "r", encoding=encoding, errors="replace") as f:
            return f.read()
    except (OSError, PermissionError) as e:
        error_msg = getattr(e, "strerror", str(e).split(":")[0])
        logger.warning(f"Cannot read file '{filepath}': {error_msg}")
        return None


def read_file_bytes(filepath: str, max_bytes: int | None = None) -> bytes | None:
    """Read a file's raw bytes with error handling.

    Args:
        filepath: Path to the file.
        max_bytes: Maximum number of bytes to read (None for full file).

    Returns:
        File content as bytes, or None if reading fails.
    """
    try:
        with open(filepath, "rb") as f:
            return f.read(max_bytes) if max_bytes else f.read()
    except (OSError, PermissionError) as e:
        error_msg = getattr(e, "strerror", str(e).split(":")[0])
        logger.warning(f"Cannot read file '{filepath}': {error_msg}")
        return None


def get_code_snippet(
    filepath: str,
    line: int,
    context: int = 3,
) -> str:
    """Extract code lines around a specific line number.

    Args:
        filepath: Path to the source file.
        line: Target line number (1-indexed).
        context: Number of context lines above and below.

    Returns:
        Code snippet as a string with line numbers.
    """
    content = read_file_safe(filepath)
    if content is None:
        return ""

    lines = content.splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)

    snippet_lines = []
    for i in range(start, end):
        marker = ">>>" if i == line - 1 else "   "
        snippet_lines.append(f"{marker} {i + 1:4d} | {lines[i]}")

    return "\n".join(snippet_lines)


def count_files(
    directory: str,
    extensions: set[str] | None = None,
    exclude_dirs: set[str] | None = None,
) -> int:
    """Count files matching criteria without reading them.

    Args:
        directory: Root directory to search.
        extensions: File extensions to count.
        exclude_dirs: Directories to exclude.

    Returns:
        Number of matching files.
    """
    return sum(1 for _ in find_files(directory, extensions, exclude_dirs))
