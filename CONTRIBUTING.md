# Contributing to prompt-firewall

First off, thank you for considering contributing! 🛡️

prompt-firewall is a security-focused project and contributions are always welcome, whether it's new attack patterns, detector improvements, bug fixes, or documentation.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Submitting Changes](#submitting-changes)
- [Adding New Attack Patterns](#adding-new-attack-patterns)
- [Adding a New Detector](#adding-a-new-detector)
- [Testing Guidelines](#testing-guidelines)
- [Style Guide](#style-guide)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### 🐛 Reporting Bugs

For **security vulnerabilities**, please see [SECURITY.md](SECURITY.md) instead.

For regular bugs:
1. Check if the issue already exists in [GitHub Issues](https://github.com/Zijian-Ni/prompt-firewall/issues)
2. If not, open a new issue using the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md)

### 💡 Suggesting Features

Open an issue using the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md).

### 🔍 Adding Attack Patterns

This is one of the most valuable contributions! See [Adding New Attack Patterns](#adding-new-attack-patterns) below.

### 📝 Improving Documentation

PRs that fix typos, clarify explanations, or add examples are always welcome.

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/prompt-firewall.git
cd prompt-firewall

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install with dev dependencies
pip install -e ".[dev]"

# 4. Run tests to verify setup
pytest
```

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=prompt_firewall --cov-report=html

# Specific test file
pytest tests/test_firewall.py -v
```

### Linting

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Add or update tests
5. Run the full test suite: `pytest`
6. Run linting: `ruff check src/ tests/`
7. Update `CHANGELOG.md` under the `[Unreleased]` section
8. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add ROT47 encoding detection`
   - `fix: prevent ReDoS in injection pattern`
   - `docs: add FastAPI integration example`
   - `test: add canary token edge cases`
9. Push and open a Pull Request against `main`

## Adding New Attack Patterns

### Injection patterns (`src/prompt_firewall/rules/injection_patterns.json`)

```json
{
  "id": "INJ-XXX",
  "name": "short_descriptive_name",
  "pattern": "(?i)your_regex_here",
  "threat_level": "high",
  "description": "Human-readable description of what this detects"
}
```

**Threat levels**: `low` | `medium` | `high` | `critical`

**Guidelines:**
- Test with both malicious AND benign inputs to assess false positive rate
- Add test cases to `tests/fixtures/malicious_prompts.json`
- Use `(?i)` for case-insensitive matching
- Avoid catastrophic backtracking (ReDoS) — test with `python -c "import re; re.compile(r'YOUR_PATTERN')"`
- Include the ID in your PR description

### Jailbreak signatures (`src/prompt_firewall/rules/jailbreak_signatures.json`)

Same format as injection patterns, using `JB-XXX` IDs.

## Adding a New Detector

1. Create `src/prompt_firewall/detectors/mydetector.py`:

```python
from prompt_firewall.detectors.base import BaseDetector
from prompt_firewall.models import DetectorResult, ThreatLevel

class MyDetector(BaseDetector):
    name = "mydetector"

    def scan(self, text: str) -> DetectorResult:
        # Your logic here
        triggered = False
        matches = []
        # ...
        return DetectorResult(
            detector=self.name,
            triggered=triggered,
            threat_level=ThreatLevel.SAFE if not triggered else ThreatLevel.HIGH,
            matches=matches,
            explanation="...",
            confidence=0.0,
        )
```

2. Register it in `src/prompt_firewall/detectors/__init__.py`
3. Add it to `_ALL_DETECTOR_CLASSES` in `src/prompt_firewall/scanner.py`
4. Add tests in `tests/test_detectors/test_mydetector.py`

## Testing Guidelines

- Every new pattern **must** have at least one test case in `tests/fixtures/malicious_prompts.json`
- New detectors **must** have both positive and negative test cases
- Aim for < 20% false positive rate on `tests/fixtures/benign_prompts.json`
- For ReDoS safety, test your patterns against long inputs

## Style Guide

- Python 3.10+ features are welcome (match/case, `X | Y` union types)
- Use type hints everywhere
- Docstrings for all public API
- Max line length: 100 characters
- `ruff` enforces the rest

## Questions?

Open a [Discussion](https://github.com/Zijian-Ni/prompt-firewall/discussions) or tag `@Zijian-Ni` in an issue.
