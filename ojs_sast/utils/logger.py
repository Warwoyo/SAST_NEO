"""Logging configuration for OJS-SAST."""

import logging
import sys


class ColoredFormatter(logging.Formatter):
    """Custom formatter with ANSI color support for terminal output."""

    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[1;31m", # Bold Red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logger(
    name: str = "ojs-sast",
    level: int = logging.INFO,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        name: Logger name.
        level: Logging level.
        log_file: Optional path for file logging.

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_fmt = ColoredFormatter("%(levelname)s %(message)s")
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # Optional file handler (no colors)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    return logger


# Global logger instance
logger = setup_logger()
