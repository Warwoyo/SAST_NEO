Building OJS-SAST (Static Application Security Testing for Open Journal Systems)

PROJECT CONTEXT

You are an AI coding agent tasked with building a SAST (Static Application Security Testing) tool specifically designed to analyze the security of Open Journal Systems (OJS) installations. This tool utilizes taint analysis as its core detection mechanism and is designed to run as a CLI tool intended for OJS administrators, security researchers, and DevSecOps teams.

OJS is an open-source academic journal management platform built on PHP. This tool must be capable of analyzing three security dimensions simultaneously: source code, system configurations, and user-uploaded files.

MAIN OBJECTIVES

Build the OJS-SAST tool with the capabilities to:

Scan OJS PHP/JS source code using rule-based taint analysis.

Audit OJS configurations (config.inc.php) and web server configurations (Nginx, Apache).

Validate and scan files uploaded to the OJS upload directories.

Mandatory Output: Automatically generate comprehensive finding reports in three formats simultaneously (JSON, HTML, SARIF) categorized by severity and security standards (CVE, CWE, OWASP Top 10), saved in a timestamped folder.

TECHNOLOGY STACK

Primary Language: Python 3.10+

PHP Parser: phply or tree-sitter with PHP grammar (use tree-sitter-php)

Config Parser: configparser, pyparsing, regex for Nginx/Apache formats

File Detection: python-magic (libmagic binding) for magic bytes

Report Formats: JSON, HTML (Jinja2), SARIF 2.1.0

CLI: click or argparse

Testing: pytest

Rule Management: YAML (via pyyaml)

Project Structure: Modular, rule-plugin based

SYSTEM ARCHITECTURE

ojs_sast/
├── cli.py                        # CLI Entry point
├── engine/
│   ├── __init__.py
│   ├── scanner.py                # Main orchestrator
│   ├── taint/
│   │   ├── __init__.py
│   │   ├── analyzer.py           # Taint analysis engine
│   │   ├── sources.py            # Taint sources definitions (user input)
│   │   ├── sinks.py              # Taint sinks definitions (dangerous functions)
│   │   └── sanitizers.py         # Valid sanitizers/validators definitions
│   └── ast_walker.py             # AST traversal helper
├── categories/
│   ├── source_code/
│   │   ├── __init__.py
│   │   ├── scanner.py            # Source code scanner
│   │   ├── php_parser.py         # PHP Parser via tree-sitter
│   │   └── rules/
│   │       ├── injection/        
│   │       ├── auth/             
│   │       ├── exposure/         
│   │       ├── file_ops/         
│   │       ├── crypto/           
│   │       ├── ojs_specific/     
│   │       └── misc/
│   ├── config/
│   │   ├── __init__.py
│   │   ├── scanner.py            # Configuration scanner
│   │   ├── parsers/
│   │   │   ├── ojs_config.py     # config.inc.php parser
│   │   │   ├── nginx_parser.py   # Nginx configuration parser
│   │   │   └── apache_parser.py  # Apache configuration parser
│   │   └── rules/
│   │       ├── ojs/
│   │       ├── nginx/
│   │       └── apache/
│   └── uploaded_file/
│       ├── __init__.py
│       ├── scanner.py            # File upload scanner
│       ├── validator.py          # Extension & MIME type validation
│       ├── magic_detector.py     # Magic bytes detector
│       └── rules/
│           ├── allowed_extensions.yaml
│           ├── dangerous_patterns.yaml
│           └── webshell_signatures.yaml
├── models/
│   ├── finding.py                # Finding data model
│   ├── rule.py                   # Rule data model
│   └── report.py                 # Report data model
├── reporters/
│   ├── json_reporter.py
│   ├── html_reporter.py          # Jinja2 templates
│   ├── sarif_reporter.py         # SARIF 2.1.0 format
│   └── templates/
│       └── report.html.j2
├── rules/                        # Rule loader and validator
│   ├── loader.py
│   └── validator.py
├── utils/
│   ├── file_utils.py
│   ├── logger.py
│   └── ojs_detector.py           # OJS installation & version detection
├── tests/
│   ├── fixtures/                 # Example files for testing
│   ├── test_taint_engine.py
│   ├── test_source_code.py
│   ├── test_config.py
│   └── test_uploaded_file.py
├── config/
│   └── default_settings.yaml     # Tool default configuration
└── results/                      # Automatically generated directory for all scan reports
    └── <timestamp>/              # Folder for each scan (e.g., 20250101_120000)


PART 1: TAINT ANALYSIS ENGINE

1.1 Basic Concepts

Implement data-flow tracking taint analysis with three main components:

TAINT SOURCES — Data entry points from users (untrusted data):

TAINT_SOURCES = {
    "superglobals": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"],
    "ojs_request": [
        "Request::getUserVar()",
        "Request::getQueryString()",
        "$request->getUserVar()",
        "$request->getQueryArray()",
        "PKPRequest::getUserVar()",
    ],
    "database_reads": [
        "DAOResultFactory",
        "->getById()",
        "->retrieve()",
    ],
    "file_reads": ["file_get_contents()", "fread()", "fgets()"],
    "env_vars": ["getenv()", "$_ENV"],
}


TAINT SINKS — Dangerous functions/operations that must not receive tainted data without proper sanitization:

TAINT_SINKS = {
    "sql_injection": [
        "->query()", "->retrieve()", "->update()", "mysql_query()",
        "mysqli_query()", "PDO::query()", "pg_query()",
    ],
    "xss": [
        "echo", "print", "printf()", "<<<EOT", "->assign()",
        "Smarty::display()", "$templateMgr->assign()",
    ],
    "rce": [
        "exec()", "shell_exec()", "system()", "passthru()",
        "popen()", "proc_open()", "eval()", "assert()",
        "preg_replace()", "create_function()",
    ],
    "file_ops": [
        "include()", "include_once()", "require()", "require_once()",
        "file_get_contents()", "fopen()", "unlink()", "rename()",
        "move_uploaded_file()", "copy()",
    ],
    "ssrf": [
        "curl_exec()", "file_get_contents()", "fsockopen()",
        "Http::request()", "fopen()",
    ],
    "xxe": ["simplexml_load_string()", "DOMDocument::load()", "XMLReader::open()"],
    "deserialization": ["unserialize()", "yaml_parse()", "json_decode()"],
    "header_injection": ["header()", "setcookie()"],
    "ldap": ["ldap_search()", "ldap_bind()"],
}


SANITIZERS — Functions considered to clean/sanitize taint:

SANITIZERS = {
    "sql": [
        "->escapeString()", "PDO::quote()", "mysqli_real_escape_string()",
        "intval()", "floatval()", "is_numeric()",
        "Capsule::schema()", # OJS Eloquent
    ],
    "xss": [
        "htmlspecialchars()", "htmlentities()", "strip_tags()",
        "PKPString::stripUnsafeHtml()", "Application::getHtmlPurifier()",
        "xss_clean()",
    ],
    "path": [
        "basename()", "realpath()", "str_replace('../', '')",
        "Import::validatePath()",
    ],
    "general": [
        "filter_var()", "filter_input()", "preg_replace()",
        "ctype_alpha()", "ctype_digit()",
    ],
}


1.2 Taint Analysis Algorithm

Implement forward data-flow analysis with the following approach:

1. Parse PHP files → AST (tree-sitter)
2. Identify all taint sources in the AST
3. Mark variables receiving values from a taint source as "tainted"
4. Follow data flow: if a tainted variable is assigned to another variable, 
   the latter becomes tainted (taint propagation)
5. If a tainted variable enters a sanitizer → remove taint
6. If a tainted variable reaches a sink → FINDING
7. Log: source, sink, taint path, location (file:line)


Each Finding must store:

taint_path: A complete list of the path from source to sink

source_location: File and line where the taint originated

sink_location: File and line where the taint reached the sink

sanitized: Whether any sanitization attempt was made (even if ineffective)

PART 2: source_code CATEGORY

2.1 Source Code Scanner

This scanner is tasked to:

Find all PHP, JS, and Smarty template files in the OJS directory

Exclude cache/, lib/vendor/, node_modules/ directories

Run taint analysis on every PHP file

Run pattern matching (regex/AST) based on YAML rules

2.2 YAML Rule Format

Each rule must follow this format:

# Example: rules/injection/sqli.yaml
rules:
  - id: "OJS-SC-SQLI-001"
    name: "SQL Injection via tainted input in raw query"
    description: >
      Data from user input flows directly into a database query function
      without adequate sanitization, allowing an attacker to manipulate the SQL query.
    severity: "CRITICAL"          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: "source_code"
    subcategory: "injection"
    cwe: "CWE-89"
    owasp: "A03:2021"
    cve_references: []            # Fill in if the rule is based on a specific CVE
    ojs_versions_affected: "all"  # or "< 3.3.0" etc.
    taint_analysis:
      sources:
        - "$_GET"
        - "$_POST"
        - "Request::getUserVar()"
      sinks:
        - "->query()"
        - "->retrieve()"
      sanitizers:
        - "->escapeString()"
        - "intval()"
    pattern_match:                # Fallback if taint analysis is insufficient
      type: "regex"               # regex | ast_pattern
      patterns:
        - '\$_(?:GET|POST|REQUEST)\[.+?\].*?->(?:query|retrieve|update)\('
    remediation: >
      Use prepared statements or ensure every input is escaped
      using `$this->_driver->escapeString()` before being inserted into a query.
    references:
      - "[https://ojs-community.pkp.sfu.ca/security](https://ojs-community.pkp.sfu.ca/security)"
      - "[https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)"
    false_positive_notes: >
      Note cases where values are validated with intval() or
      is_numeric() beforehand — this is not a false positive if casting is done.


2.3 Source Code Sub-Categories

Implement rules for each of the following sub-categories:

2.3.1 injection/

sqli.yaml: SQL Injection — raw query with tainted input, OJS DAOResultFactory

xss.yaml: XSS — reflected/stored, including $templateMgr->assign() without escape

rce.yaml: Remote Code Execution — eval(), exec(), preg_replace with /e

xxe.yaml: XML External Entity — XML parsing without LIBXML_NOENT disabled

ssti.yaml: Server-Side Template Injection — Smarty template with tainted input

2.3.2 auth/

broken_auth.yaml: Weak authentication — session fixation, weak token generation

idor.yaml: Insecure Direct Object Reference — object access without ownership validation

csrf.yaml: Cross-Site Request Forgery — form actions without CSRF token validation

2.3.3 exposure/

sensitive_data.yaml: Hardcoded credentials, API keys, passwords in code

debug_leak.yaml: Debug info, stack trace, leftover var_dump() in production

2.3.4 file_ops/

path_traversal.yaml: Path traversal — ../ in fopen, include arguments

file_inclusion.yaml: Local/Remote File Inclusion — include($_GET['page'])

unsafe_upload.yaml: Dangerous file uploads — bypassable extension validations

2.3.5 crypto/

weak_hash.yaml: Weak hash algorithms — md5(), sha1() for passwords

weak_rand.yaml: Insecure randomness — rand(), mt_rand() for security tokens

2.3.6 ojs_specific/

plugin_vuln.yaml: Vulnerabilities in the OJS plugin mechanism

hook_injection.yaml: Abusable OJS hook system

cve_ojs.yaml: Rules based on documented OJS CVEs:

CVE-2023-33970 (XSS via galley)

CVE-2022-24822 (RCE via file upload)

CVE-2021-27231 (Path traversal)

CVE-2020-28113 (SSRF)

(add relevant newer CVEs)

2.3.7 misc/

deserialization.yaml: Unsafe deserialization — unserialize() with tainted data

ssrf.yaml: Server-Side Request Forgery — curl/file_get_contents with tainted URL

PART 3: config CATEGORY

3.1 Configuration Scanner

This scanner is tasked to:

Detect and parse the OJS config.inc.php file

Detect and parse Nginx (.conf) and Apache (.conf, .htaccess) configuration files

Compare actual configuration values with security rules

Report configurations deviating from best practices

3.2 OJS Config Sub-Category (config/rules/ojs/)

database.yaml

Check values in the [database] section in config.inc.php:

checks:
  - id: "OJS-CFG-DB-001"
    name: "Database password not set"
    field: "database.password"
    condition: "empty"
    severity: "CRITICAL"
  - id: "OJS-CFG-DB-002"
    name: "Database host uses default value"
    field: "database.host"
    condition: "equals"
    value: "localhost"
    severity: "INFO"
    note: "Ensure the database is not accessible externally"
  - id: "OJS-CFG-DB-003"
    name: "Insecure database driver"
    field: "database.driver"
    condition: "not_in"
    allowed_values: ["mysqli", "pgsql"]
    severity: "HIGH"


security_settings.yaml

Check the [security] section:

security.salt using default or empty values (CRITICAL)

security.force_ssl not set to On (HIGH)

security.allowed_hosts empty or wildcard (HIGH)

security.disable_path_info not set to Off (MEDIUM)

email.yaml

Check the [email] section:

SMTP using plain authentication without TLS

SMTP password stored in plaintext

allow_envelope_sender enabled without restrictions

files.yaml

Check the [files] section:

files_dir located inside the web server's document root (should be outside)

public_files_dir publicly accessible containing dangerous extensions

Upload size excessively large

3.3 Nginx Config Sub-Category (config/rules/nginx/)

Check for secure configurations, including:

Legacy TLS protocols permitted (TLSv1, TLSv1.1)

HSTS not configured

Weak cipher suites permitted

Missing security headers (X-Frame-Options, X-Content-Type-Options, CSP)

Access control for sensitive directories (classes/, lib/, tools/)

Disabling PHP execution in upload directories

3.4 Apache Config Sub-Category (config/rules/apache/)

Equivalent checks to Nginx, plus:

ServerTokens Prod and ServerSignature Off

.htaccess: Detection of dangerous Options Indexes

mod_status and mod_info active without IP restriction

PART 4: uploaded_file CATEGORY

4.1 File Upload Scanner

This scanner is tasked to:

Automatically locate the OJS upload directories based on files_dir and public_files_dir in config.inc.php, or via CLI arguments.

Validate extensions — compare each file to the allowed extension list per upload context (see 4.2).

Detect magic bytes — if an extension is mismatched, read the file's first bytes to identify its true type.

If a suspicious file is found (especially .php, .phtml, .php3, etc.):

Instantly trigger a CRITICAL severity alert.

Run a content scan on the file using rules from the source_code category (specifically: webshell signatures, eval patterns, reverse shell patterns).

Analyze non-PHP file content: Check for embedded payloads in PDFs (JavaScript, auto-open execution) or Office files with macros.

4.2 Allowed Extensions List (allowed_extensions.yaml)

Provide contexts such as submission_file, galley, cover_image, plugin_zip, etc., with strict allowed extensions and size limits. Define dangerous extensions (e.g., .php, .htaccess, .js) categorized by risk level.

4.3 Webshell and Payload Detection

Suspicious files must be scanned using dangerous_patterns.yaml and webshell_signatures.yaml (looking for eval, base64_decode, reverse shell sockets, and common webshell identifiers).

PART 5: DATA MODELS

5.1 Finding Model (models/finding.py)

from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Category(Enum):
    SOURCE_CODE = "source_code"
    CONFIG = "config"
    UPLOADED_FILE = "uploaded_file"

@dataclass
class TaintPath:
    source: str
    source_location: str  # "file.php:42"
    sink: str
    sink_location: str
    intermediate_steps: List[str] = field(default_factory=list)
    sanitized: bool = False

@dataclass
class Finding:
    id: str                          
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    subcategory: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str                
    cwe: Optional[str] = None        
    owasp: Optional[str] = None      
    cve_references: List[str] = field(default_factory=list)
    taint_path: Optional[TaintPath] = None
    remediation: str = ""
    false_positive_likelihood: str = "LOW"  
    references: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


5.2 Report Model (models/report.py)

@dataclass
class ScanReport:
    scan_id: str
    timestamp: str
    ojs_version: Optional[str]
    ojs_path: str
    scan_duration_seconds: float
    findings: List[Finding]
    summary: dict  # {CRITICAL: n, HIGH: n, ...}
    scanner_version: str
    categories_scanned: List[str]
    files_scanned: int
    rules_loaded: int


PART 6: CLI INTERFACE

6.1 CLI Commands

IMPORTANT: The user no longer needs to specify --output. The tool MUST ALWAYS generate JSON, HTML, and SARIF automatically.

# Full scan (all categories, automatically generates JSON, HTML, SARIF)
ojs-sast scan /path/to/ojs

# Scan specific category
ojs-sast scan /path/to/ojs --category source_code
ojs-sast scan /path/to/ojs --category config
ojs-sast scan /path/to/ojs --category uploaded_file

# Scan with separate web server configurations
ojs-sast scan /path/to/ojs --nginx-config /etc/nginx/sites-available/ojs.conf
ojs-sast scan /path/to/ojs --apache-config /etc/apache2/sites-available/ojs.conf

# Filter by severity
ojs-sast scan /path/to/ojs --min-severity HIGH

# Show summary only (Reports are still generated in the background)
ojs-sast scan /path/to/ojs --summary-only

# Available rules management
ojs-sast rules list
ojs-sast rules list --category source_code
ojs-sast rules show OJS-SC-SQLI-001

# Verify OJS installation
ojs-sast detect /path/to/ojs


6.2 CLI Output (Example)

OJS-SAST v1.0.0 | Scanning: /var/www/ojs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[source_code] Scanning PHP files...         ██████████ 847 files
[config]      Scanning config.inc.php...    ██████████ done
[config]      Scanning nginx.conf...        ██████████ done
[uploaded]    Scanning uploads directory... ██████████ 1,203 files

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] OJS-UF-WS-001 — PHP eval webshell detected
  File: /var/www/ojs/public/files/submission/22/article.php
  Line: 1
  Code: eval(base64_decode('...'));
  Path: uploaded_file > dangerous_extensions > webshell scan
  Fix:  Delete the file immediately and audit server upload access.

[CRITICAL] OJS-SC-SQLI-001 — SQL Injection via tainted input
  File: /var/www/ojs/classes/submission/SubmissionDAO.php:234
  Taint: $_GET['id'] → $submissionId → $this->retrieve($submissionId)
  CWE:  CWE-89 | OWASP: A03:2021
  Fix:  Use intval() or prepared statement.

[HIGH]     OJS-CFG-SEC-001 — Security salt uses default value
  File: /var/www/ojs/config.inc.php
  Line: [security] salt = defaultSalt
  Fix:  Replace with a long, unique, random value.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUMMARY: 3 CRITICAL | 7 HIGH | 12 MEDIUM | 5 LOW | 3 INFO
Duration: 23.4s | Files: 2,050 | Rules: 142
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[✔] Scan Complete! Reports have been automatically generated.
[✔] Output Directory: /absolute/path/to/ojs_sast/results/20250101_120000/
    📄 report.json
    📄 report.html
    📄 report.sarif


PART 7: REPORTS

7.1 Mandatory Output Generation Logic

The tool MUST automatically generate all three of the following formats once a scan is completed.
The files must be saved under the ojs_sast/results/ directory inside a dynamically created subfolder named based on the scan's timestamp (e.g., YYYYMMDD_HHMMSS/).

7.2 JSON Report

A machine-readable standard JSON schema capturing scan metadata, summary, and the array of findings including line numbers, code snippets, and taint paths.

7.3 SARIF 2.1.0 Report

Implement a SARIF (Static Analysis Results Interchange Format) output compatible with GitHub Code Scanning and VS Code SARIF Viewer.

7.4 HTML Report

Build an interactive HTML template (Jinja2) featuring:

Executive summary with severity distribution charts.

Sortable/filterable findings table.

Detailed findings with syntax-highlighted code snippets.

Taint path visualization.

Remediation section per finding.

PART 8: OJS DETECTOR

Build utils/ojs_detector.py that:

Detects if the target directory is a valid OJS installation.

Reads the OJS version from pkp-lib/registry/app-version.json or falls back to dbscripts/xml/version.xml.

Detects the paths of config.inc.php, public/, and lib/.

Issues a warning if an outdated/vulnerable OJS version is detected.

PART 9: TESTING

Create a comprehensive test suite using pytest:

9.1 Fixtures

Provide a tests/fixtures/ directory containing:

php_vulnerable/: PHP files with known vulnerabilities (true positive testing).

php_safe/: PHP files that are properly sanitized/fixed (false positive testing).

config/: OJS and web server configuration files covering various edge cases.

uploads/: Uploaded files simulating normal and malicious extensions/payloads.

9.2 Critical Test Cases

Ensure robust test coverage including verifying taint flows, sanitizer effectiveness, magic byte detection against obfuscated files, etc.

PART 10: IMPLEMENTATION GUIDE & PRIORITIES

Suggested Order of Execution

Phase 1 — Foundation:

Set up project structure, dependency management (pyproject.toml).

Implement data models (finding.py, rule.py, report.py).

Implement the YAML rule loader.

Implement the OJS detector.

Phase 2 — Taint Engine:

Integrate tree-sitter-php for PHP to AST parsing.

Implement engine/taint/analyzer.py with forward data-flow.

Define sources, sinks, and sanitizers.

Phase 3 — Source Code Scanner:

Implement the scanner utilizing YAML rules.

Write at least 3 rules per sub-category.

Write tests for each rule.

Phase 4 — Config Scanner:

Implement config.inc.php, Nginx, and Apache parsers.

Build configuration rules.

Phase 5 — Upload Scanner:

Implement extension validator and magic bytes detector.

Implement webshell scanner and link it to the source code scanner.

Phase 6 — Output & CLI:

Implement CLI using click.

Crucial: Implement logic to automatically dump JSON, HTML, and SARIF reporters into the timestamped results/ folder simultaneously.

Display the absolute path to the results folder at the end of the CLI execution.

Phase 7 — Polishing:

Complete the test suite.

Add progress bars and comprehensive logging.

Document README.md and CONTRIBUTING.md.

IMPORTANT NOTES FOR THE AGENT

Accuracy is more important than speed: It is better to miss a finding than to generate too many false positives, as high false positive rates erode user trust.

Every rule must have tests: Never create a rule without including a PHP fixture for a true positive and one for a false positive.

Taint paths must be informative: Output must clearly show where data originates and where it goes, allowing developers to immediately grasp the issue.

Handle edge cases: Exceptionally large files, binary files with incorrect extensions, configurations using include/extends, and multi-site OJS installations.

CVE-based rules must be accurate: Include the CVE reference, affected OJS versions, and an actual payload example (in YAML comments, NOT as active exploits).

Use defensive parsing: Parsers must not crash when encountering syntactically invalid PHP code—skip the file with a warning.

File permissions: The scanner is strictly read-only. It must never write to or modify the target files. The only write operations are placing the reports inside the internal results/ directory.

This prompt is a living document. After the initial phase is completed, report back on:
1. Which rules are generating high false positives and require refinement.
2. Which parser components represent the slowest bottlenecks.
3. Any new finding types discovered that lack existing rules.