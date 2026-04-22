# Contributing to OJS-SAST

First off, thank you for considering contributing to OJS-SAST! This tool is built by the community to help secure academic publishing infrastructure worldwide.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ojs-sast/ojs-sast.git
   cd ojs-sast
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Install system dependencies:**
   - `libmagic` (for file type detection):
     - Debian/Ubuntu: `sudo apt-get install libmagic1`
     - macOS: `brew install libmagic`

## Testing

We use `pytest` for all our testing.

- Run the full test suite:
  ```bash
  pytest
  ```
- Run tests with coverage:
  ```bash
  pytest --cov=ojs_sast --cov-report=term-missing
  ```

**Important:** Never create a new rule without including a PHP/Config/Upload fixture for a true positive AND one for a false positive in the `tests/fixtures/` directory.

## Writing Rules

OJS-SAST uses YAML files to define security rules. They are located in `ojs_sast/categories/`.

### 1. Source Code Rules (`source_code/rules/`)

Source code rules support both **Taint Analysis** and **Regex Pattern Matching**.

```yaml
rules:
  - id: "OJS-SC-EX-001"
    name: "Example Rule"
    description: "Detailed description of the vulnerability."
    severity: "HIGH"
    category: "source_code"
    subcategory: "injection"
    cwe: "CWE-XX"
    owasp: "A0X:2021"
    taint_analysis:
      sources:
        - "$_GET"
      sinks:
        - "dangerous_function"
      sanitizers:
        - "safe_function"
    pattern_match:
      type: "regex"
      patterns:
        - 'dangerous_function\s*\(.*?\$_GET'
    remediation: "How to fix this issue."
```

### 2. Configuration Rules (`config/rules/`)

Config rules use `config_check` to query specific parser outputs.

```yaml
checks:
  - id: "OJS-CFG-EX-001"
    name: "Example Config Rule"
    description: "Checks if a setting is missing."
    severity: "MEDIUM"
    category: "config"
    subcategory: "ojs"
    config_check:
      field: "database.password"
      condition: "empty"
```

Valid conditions: `empty`, `equals`, `not_equals`, `not_in`, `contains`, `not_contains`, `missing`, `regex_match`.

### 3. Upload Rules (`uploaded_file/rules/`)

Upload rules define dangerous extensions or regex patterns for identifying malicious code within uploaded files (like webshells).

## Code Style

- We use **Type Hinting** extensively. Please ensure all new functions have appropriate type hints.
- We use **Dataclasses** for data models.
- Code should be formatted properly. We recommend using `black` and `isort`.
- Keep the scanner read-only. We strictly NEVER modify user files.

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Add your new rules or features.
3. Add corresponding test fixtures and ensure `pytest` passes.
4. Update documentation if necessary.
5. Open a Pull Request with a clear description of the problem and the proposed solution.

## Reporting Issues

If you find a bug or false positive, please open an issue with:
- The rule ID that triggered the false positive.
- The code snippet that caused it.
- Why it is a false positive.
- (Optional) A proposed fix to the rule's regex or taint definitions.
