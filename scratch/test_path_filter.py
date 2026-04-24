import os
import fnmatch
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Rule:
    id: str
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)

def should_run_rule(rule: Rule, filepath: str, target_path: str) -> bool:
    # Relative path for matching
    rel_path = os.path.relpath(filepath, target_path)

    # 1. Check exclude_paths (Blacklist takes precedence)
    if rule.exclude_paths:
        for pattern in rule.exclude_paths:
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(filepath, pattern):
                return False

    # 2. Check include_paths (Whitelist)
    if rule.include_paths:
        included = False
        for pattern in rule.include_paths:
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(filepath, pattern):
                included = True
                break
        if not included:
            return False

    return True

# Test cases
target = "/var/www/ojs"
rule = Rule(
    id="TEST-001",
    include_paths=["**/*Handler.inc.php"],
    exclude_paths=["**/*DAO.inc.php", "**/classes/**"]
)

test_files = [
    "/var/www/ojs/pages/index/IndexHandler.inc.php", # Should be True
    "/var/www/ojs/classes/core/SomeClass.inc.php",    # Should be False (not in include, and in exclude)
    "/var/www/ojs/lib/pkp/classes/db/DAO.inc.php",   # Should be False (matches exclude)
    "/var/www/ojs/pages/about/AboutHandler.inc.php", # Should be True
    "/var/www/ojs/some/other/file.php"               # Should be False (not in include)
]

for f in test_files:
    print(f"File: {f} -> Should Run: {should_run_rule(rule, f, target)}")
