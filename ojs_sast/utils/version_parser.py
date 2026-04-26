"""OJS version comparison utility for CVE rule filtering.

Parses complex OJS version range strings (e.g., '<= 3.4.0-3')
and compares them against a target installation version to determine
if a CVE rule should be applied.
"""

import re
from functools import lru_cache

from packaging.version import Version, InvalidVersion

from ojs_sast.utils.logger import logger


def _normalize_ojs_version(version_str: str) -> Version:
    """Convert OJS version string to a packaging.version.Version.

    OJS uses hyphens for build numbers (e.g., '3.4.0-3') which
    packaging interprets as pre-release. We convert to dot notation
    so that 3.4.0-3 becomes 3.4.0.3, ensuring correct ordering.
    """
    normalized = version_str.strip().replace("-", ".")
    return Version(normalized)


def _parse_single_constraint(constraint: str) -> tuple[str, Version] | None:
    """Parse a single version constraint like '<= 3.4.0-3'.

    Returns:
        Tuple of (operator, version) or None if parsing fails.
    """
    constraint = constraint.strip()
    if not constraint:
        return None

    match = re.match(r"^(<=|>=|<|>|==|=)\s*(.+)$", constraint)
    if not match:
        # Try bare version (implies ==)
        try:
            ver = _normalize_ojs_version(constraint)
            return ("==", ver)
        except InvalidVersion:
            return None

    op = match.group(1)
    if op == "=":
        op = "=="
    try:
        ver = _normalize_ojs_version(match.group(2))
        return (op, ver)
    except InvalidVersion:
        logger.debug(f"Could not parse version constraint: {constraint}")
        return None


def _check_constraint(target: Version, op: str, bound: Version) -> bool:
    """Check if target satisfies a single constraint."""
    if op == "<=":
        return target <= bound
    elif op == ">=":
        return target >= bound
    elif op == "<":
        return target < bound
    elif op == ">":
        return target > bound
    elif op == "==":
        return target == bound
    return False


def is_version_vulnerable(version_spec: str, target_version: str) -> bool:
    """Check if a target OJS version is vulnerable according to a rule spec.

    The version_spec is a comma/and-separated list of constraints.
    The target is vulnerable if it satisfies ANY one of the constraints
    (OR logic across groups separated by 'and' or ',').

    Args:
        version_spec: Version range string from the rule
                      (e.g., '<= 3.3.0-21, <= 3.4.0-9, and <= 3.5.0-1').
        target_version: The detected OJS installation version.

    Returns:
        True if the target version falls within the vulnerable range.
    """
    if not version_spec or version_spec.lower() in ("all", "*"):
        return True

    if not target_version:
        # If we can't determine the version, assume vulnerable (safe default)
        return True

    try:
        target = _normalize_ojs_version(target_version)
    except InvalidVersion:
        logger.debug(f"Could not parse target version: {target_version}")
        return True  # Assume vulnerable if we can't parse

    # Split by comma and/or 'and' to get individual constraints
    # e.g., '<= 3.3.0-21, <= 3.4.0-9, and <= 3.5.0-1'
    parts = re.split(r"\s*(?:,\s*(?:and\s*)?|and\s+)", version_spec)

    for part in parts:
        part = part.strip()
        if not part:
            continue

        parsed = _parse_single_constraint(part)
        if parsed is None:
            continue

        op, bound = parsed
        if _check_constraint(target, op, bound):
            return True

    return False
