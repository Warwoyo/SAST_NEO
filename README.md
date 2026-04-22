# OJS-SAST

**Static Application Security Testing for Open Journal Systems**

A comprehensive SAST tool specifically designed to analyze the security of [Open Journal Systems (OJS)](https://pkp.sfu.ca/software/ojs/) installations. Uses taint analysis as its core detection mechanism.

## Features

- **Source Code Scanning** — PHP taint analysis via tree-sitter AST + YAML rule-based pattern matching
- **Configuration Auditing** — OJS `config.inc.php`, Nginx, and Apache configuration analysis
- **Uploaded File Scanning** — Magic byte detection, extension validation, webshell signature scanning
- **Multi-format Reports** — Automatically generates JSON, HTML, and SARIF 2.1.0 reports

## Installation

```bash
# Clone the repository
git clone https://github.com/ojs-sast/ojs-sast.git
cd ojs-sast

# Install in development mode
pip install -e ".[dev]"
```

### System Dependencies

- **Python 3.10+**
- **libmagic** (for python-magic file type detection):
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libmagic1
  # macOS
  brew install libmagic
  ```

## Quick Start

```bash
# Full scan (generates JSON, HTML, SARIF automatically)
ojs-sast scan /path/to/ojs

# Scan specific category
ojs-sast scan /path/to/ojs --category source_code
ojs-sast scan /path/to/ojs --category config
ojs-sast scan /path/to/ojs --category uploaded_file

# Include web server config
ojs-sast scan /path/to/ojs --nginx-config /etc/nginx/sites-available/ojs.conf

# Filter by severity
ojs-sast scan /path/to/ojs --min-severity HIGH

# Show summary only
ojs-sast scan /path/to/ojs --summary-only

# List available rules
ojs-sast rules list
ojs-sast rules list --category source_code

# Show rule details
ojs-sast rules show OJS-SC-SQLI-001

# Detect OJS installation
ojs-sast detect /path/to/ojs
```

## Architecture

```
ojs_sast/
├── cli.py                          # CLI entry point (Click)
├── engine/
│   ├── scanner.py                  # Main orchestrator
│   ├── ast_walker.py               # AST traversal helpers
│   └── taint/
│       ├── analyzer.py             # Taint analysis engine
│       ├── sources.py              # Taint source definitions
│       ├── sinks.py                # Taint sink definitions
│       └── sanitizers.py           # Sanitizer definitions
├── categories/
│   ├── source_code/                # PHP/JS source scanning
│   │   ├── scanner.py
│   │   ├── php_parser.py           # tree-sitter PHP parser
│   │   └── rules/                  # 20 YAML rule files
│   ├── config/                     # Configuration auditing
│   │   ├── scanner.py
│   │   ├── parsers/                # OJS, Nginx, Apache parsers
│   │   └── rules/                  # 6 config rule files
│   └── uploaded_file/              # Upload scanning
│       ├── scanner.py
│       ├── validator.py            # Extension validation
│       ├── magic_detector.py       # Magic byte detection
│       └── rules/                  # 3 upload rule files
├── models/                         # Data models (Finding, Rule, Report)
├── reporters/                      # JSON, HTML, SARIF generators
├── rules/                          # Rule loader & validator
└── utils/                          # Logger, file utils, OJS detector
```

## Security Standards

Rules are mapped to industry security standards:

| Standard | Coverage |
|----------|----------|
| **CWE** | CWE-22, CWE-78, CWE-79, CWE-89, CWE-94, CWE-330, CWE-434, CWE-502, CWE-611, CWE-798, CWE-918 |
| **OWASP Top 10 (2021)** | A01-A10 |
| **OJS CVEs** | CVE-2020-28113, CVE-2021-27231, CVE-2022-24822, CVE-2023-33970 |

## Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=ojs_sast --cov-report=term-missing
```

## License

MIT
