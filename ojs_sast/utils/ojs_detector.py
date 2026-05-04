"""OJS installation detection and version identification."""

import json
import os
import re
from dataclasses import dataclass
from typing import Optional

from ojs_sast.utils.file_utils import read_file_safe
from ojs_sast.utils.logger import logger

# Known vulnerable OJS versions with associated CVEs
KNOWN_VULNERABLE_VERSIONS = {
    "3.3.0-13": ["CVE-2023-33970"],
    "3.3.0-10": ["CVE-2022-24822"],
    "3.2.1-4": ["CVE-2021-27231"],
    "3.2.0-3": ["CVE-2020-28113"],
    "3.1.2-4": ["CVE-2020-28113"],
}


@dataclass
class OJSInstallation:
    """Detected OJS installation details."""
    is_valid: bool
    version: Optional[str]
    base_path: str
    config_path: Optional[str]
    public_dir: Optional[str]
    lib_dir: Optional[str]
    classes_dir: Optional[str]
    plugins_dir: Optional[str]
    files_dir: Optional[str]         # from config.inc.php
    public_files_dir: Optional[str]  # from config.inc.php
    known_vulnerabilities: list[str]
    warnings: list[str]


def detect_ojs(target_path: str) -> OJSInstallation:
    """Detect if the target directory is a valid OJS installation.

    Checks for characteristic OJS directory structure and files,
    reads version information, and identifies known vulnerabilities.

    Args:
        target_path: Path to the suspected OJS root directory.

    Returns:
        OJSInstallation dataclass with detection results.
    """
    base_path = os.path.abspath(target_path)
    warnings: list[str] = []
    known_vulns: list[str] = []

    if not os.path.isdir(base_path):
        return OJSInstallation(
            is_valid=False, version=None, base_path=base_path,
            config_path=None, public_dir=None, lib_dir=None,
            classes_dir=None, plugins_dir=None,
            files_dir=None, public_files_dir=None,
            known_vulnerabilities=[], warnings=["Target path is not a directory"],
        )

    # Check for OJS signature files/directories
    ojs_indicators = [
        "config.inc.php",
        os.path.join("classes", "core", "Application.php"),
        os.path.join("lib", "pkp"),
        "registry",
    ]

    found_indicators = 0
    for indicator in ojs_indicators:
        if os.path.exists(os.path.join(base_path, indicator)):
            found_indicators += 1

    is_valid = found_indicators >= 2  # At least 2 indicators must be present

    if not is_valid:
        warnings.append(
            f"Only {found_indicators}/4 OJS indicators found. "
            "This may not be an OJS installation."
        )

    # Detect config.inc.php
    config_path = _find_config(base_path)
    if config_path:
        logger.info(f"Found OJS config: {config_path}")
    else:
        warnings.append("config.inc.php not found")

    # Detect key directories
    public_dir = _check_dir(base_path, "public")
    lib_dir = _check_dir(base_path, "lib")
    classes_dir = _check_dir(base_path, "classes")
    plugins_dir = _check_dir(base_path, "plugins")

    # Detect version
    version = _detect_version(base_path)
    if version:
        logger.info(f"Detected OJS version: {version}")
        # Check against known vulnerable versions
        for vuln_ver, cves in KNOWN_VULNERABLE_VERSIONS.items():
            if version == vuln_ver or version.startswith(vuln_ver.rsplit("-", 1)[0]):
                known_vulns.extend(cves)
        if known_vulns:
            warnings.append(
                f"OJS {version} has known vulnerabilities: {', '.join(known_vulns)}"
            )
    else:
        warnings.append("Could not determine OJS version")

    # Parse files_dir and public_files_dir from config
    files_dir = None
    public_files_dir = None
    if config_path:
        files_dir, public_files_dir = _parse_file_dirs(config_path)

    return OJSInstallation(
        is_valid=is_valid,
        version=version,
        base_path=base_path,
        config_path=config_path,
        public_dir=public_dir,
        lib_dir=lib_dir,
        classes_dir=classes_dir,
        plugins_dir=plugins_dir,
        files_dir=files_dir,
        public_files_dir=public_files_dir,
        known_vulnerabilities=known_vulns,
        warnings=warnings,
    )


def _find_config(base_path: str) -> Optional[str]:
    """Locate config.inc.php in the OJS installation."""
    candidates = [
        os.path.join(base_path, "config.inc.php"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def _check_dir(base_path: str, dirname: str) -> Optional[str]:
    """Check if a directory exists and return its path."""
    path = os.path.join(base_path, dirname)
    return path if os.path.isdir(path) else None


def _detect_version(base_path: str) -> Optional[str]:
    """Detect OJS version from known version files.

    Tries multiple locations in order of preference:
    1. lib/pkp/registry/appVersion.xml
    2. dbscripts/xml/version.xml
    3. package.json or composer.json
    """
    # Try appVersion.xml (OJS 3.x)
    version_files = [
        os.path.join(base_path, "dbscripts", "xml", "version.xml"),
    ]

    for vfile in version_files:
        content = read_file_safe(vfile)
        if content:
            version = _parse_version_xml(content)
            if version:
                return version

    # Try package.json
    pkg_json = os.path.join(base_path, "package.json")
    content = read_file_safe(pkg_json)
    if content:
        try:
            data = json.loads(content)
            version = data.get("version")
            if version:
                return version
        except json.JSONDecodeError:
            pass

    return None


def _parse_version_xml(content: str) -> Optional[str]:
    """Parse OJS version from XML version file."""
    # Extract major, minor, revision, build from XML
    major = re.search(r"<major>(\d+)</major>", content)
    minor = re.search(r"<minor>(\d+)</minor>", content)
    revision = re.search(r"<revision>(\d+)</revision>", content)
    build = re.search(r"<build>(\d+)</build>", content)

    if major and minor and revision:
        version = f"{major.group(1)}.{minor.group(1)}.{revision.group(1)}"
        if build and build.group(1) != "0":
            version += f"-{build.group(1)}"
        return version

    # Fallback: try <release> tag
    release = re.search(r"<release>([\d.]+(?:-\d+)?)</release>", content)
    if release:
        return release.group(1)

    return None


def _parse_file_dirs(config_path: str) -> tuple[Optional[str], Optional[str]]:
    """Extract files_dir and public_files_dir from config.inc.php."""
    content = read_file_safe(config_path)
    if not content:
        return None, None

    files_dir = None
    public_files_dir = None

    files_match = re.search(r"^\s*files_dir\s*=\s*(.+)$", content, re.MULTILINE)
    if files_match:
        files_dir = files_match.group(1).strip().strip('"').strip("'")

    public_match = re.search(r"^\s*public_files_dir\s*=\s*(.+)$", content, re.MULTILINE)
    if public_match:
        public_files_dir = public_match.group(1).strip().strip('"').strip("'")

    return files_dir, public_files_dir
