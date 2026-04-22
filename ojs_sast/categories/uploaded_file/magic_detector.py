"""Magic bytes detector for file type identification.

Uses python-magic (libmagic) to detect actual file types based on
file content rather than extensions.
"""

from ojs_sast.utils.logger import logger

# Fallback magic byte signatures when python-magic is unavailable
MAGIC_SIGNATURES: dict[str, list[tuple[bytes, int]]] = {
    "application/pdf": [(b"%PDF", 0)],
    "image/jpeg": [(b"\xff\xd8\xff", 0)],
    "image/png": [(b"\x89PNG\r\n\x1a\n", 0)],
    "image/gif": [(b"GIF87a", 0), (b"GIF89a", 0)],
    "application/zip": [(b"PK\x03\x04", 0)],
    "application/gzip": [(b"\x1f\x8b", 0)],
    "text/html": [(b"<!DOCTYPE", 0), (b"<html", 0)],
    "application/x-php": [(b"<?php", 0), (b"<?=", 0), (b"<?\n", 0)],
    "application/x-elf": [(b"\x7fELF", 0)],
    "application/x-executable": [(b"MZ", 0)],
    "application/x-rar": [(b"Rar!", 0)],
    "application/x-7z": [(b"7z\xbc\xaf\x27\x1c", 0)],
    "application/msword": [(b"\xd0\xcf\x11\xe0", 0)],
}

_magic_available = False
_magic_instance = None


def _init_magic() -> None:
    """Initialize python-magic if available."""
    global _magic_available, _magic_instance
    try:
        import magic
        _magic_instance = magic.Magic(mime=True)
        _magic_available = True
        logger.debug("python-magic initialized successfully")
    except (ImportError, Exception) as e:
        _magic_available = False
        logger.debug(f"python-magic not available, using fallback: {e}")


def detect_mime_type(filepath: str) -> str | None:
    """Detect the MIME type of a file using magic bytes.

    Args:
        filepath: Path to the file.

    Returns:
        MIME type string or None if detection fails.
    """
    global _magic_available, _magic_instance

    if _magic_instance is None:
        _init_magic()

    if _magic_available and _magic_instance:
        try:
            return _magic_instance.from_file(filepath)
        except Exception as e:
            logger.debug(f"python-magic failed for {filepath}: {e}")

    # Fallback to manual magic byte detection
    return _detect_mime_fallback(filepath)


def detect_mime_from_bytes(data: bytes) -> str | None:
    """Detect MIME type from raw bytes.

    Args:
        data: File content bytes.

    Returns:
        MIME type string or None.
    """
    global _magic_available, _magic_instance

    if _magic_instance is None:
        _init_magic()

    if _magic_available and _magic_instance:
        try:
            return _magic_instance.from_buffer(data)
        except Exception:
            pass

    return _detect_mime_from_bytes_fallback(data)


def _detect_mime_fallback(filepath: str) -> str | None:
    """Fallback MIME detection using manual magic byte signatures."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
    except (OSError, PermissionError):
        return None

    return _detect_mime_from_bytes_fallback(header)


def _detect_mime_from_bytes_fallback(data: bytes) -> str | None:
    """Match bytes against known magic signatures."""
    if len(data) < 2:
        return None

    for mime_type, signatures in MAGIC_SIGNATURES.items():
        for signature, offset in signatures:
            if data[offset:offset + len(signature)] == signature:
                return mime_type

    # Check if it looks like text/plain
    try:
        data[:256].decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def is_extension_mismatch(filepath: str, expected_mime: str | None = None) -> tuple[bool, str | None, str | None]:
    """Check if a file's extension matches its actual content type.

    Args:
        filepath: Path to the file.
        expected_mime: Optional expected MIME type based on extension.

    Returns:
        Tuple of (is_mismatch, actual_mime, expected_mime).
    """
    import os

    actual_mime = detect_mime_type(filepath)
    if actual_mime is None:
        return False, None, expected_mime

    # Map common extensions to expected MIME types
    ext = os.path.splitext(filepath)[1].lower()
    ext_mime_map = {
        ".pdf": "application/pdf",
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".zip": "application/zip",
        ".xml": "text/xml",
        ".html": "text/html",
        ".txt": "text/plain",
        ".php": "application/x-php",
    }

    if expected_mime is None:
        expected_mime = ext_mime_map.get(ext)

    if expected_mime and actual_mime:
        # Normalize for comparison
        actual_base = actual_mime.split(";")[0].strip()
        is_mismatch = actual_base != expected_mime
        return is_mismatch, actual_mime, expected_mime

    return False, actual_mime, expected_mime
