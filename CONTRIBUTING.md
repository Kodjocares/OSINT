# Contributing to OSINT Tool

Thank you for contributing. This guide covers everything you need to know.

---

## Before You Start

- **All contributions must be for legitimate, authorized OSINT research only.**
- Check open [Issues](https://github.com/YOUR_USERNAME/osint-tool/issues) and [PRs](https://github.com/YOUR_USERNAME/osint-tool/pulls) to avoid duplication.
- For significant new modules, open a Feature Request issue first to discuss the approach.

---

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/osint-tool.git
cd osint-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install   # optional but recommended
```

---

## Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| New module | `feat/module-name` | `feat/linkedin-scraper` |
| Bug fix | `fix/description` | `fix/whois-timeout` |
| Docs | `docs/description` | `docs/update-readme` |
| Refactor | `refactor/description` | `refactor/helpers-cleanup` |
| CI / tooling | `ci/description` | `ci/add-safety-check` |

---

## Adding a New Module

Every module follows the same pattern:

### 1 — Create `modules/my_module.py`

```python
"""
modules/my_module.py — One-line description
What it does, what APIs it uses, free/paid
"""
import logging
from typing import Dict
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

class MyModule:
    """Docstring."""

    def lookup(self, target: str) -> Dict:
        """Main method — always returns a Dict."""
        result = {"target": target}
        resp = safe_request(f"https://some-api.example.com/{target}")
        if resp and resp.status_code == 200:
            result["data"] = resp.json()
        return result
```

### 2 — Wire into `main.py`

Add the import, instantiate in `OSINTTool.__init__`, add a numbered method, add a menu entry, and add a CLI `--flag`.

### 3 — Add API keys (if needed)

In `config.py`:
```python
MY_API_KEY = os.getenv("MY_API_KEY", "")
```

In `.env.example`:
```env
MY_API_KEY=   # Sign up at https://example.com/api
```

In `requirements.txt` if a new library is needed.

### 4 — Write tests

In `tests/test_modules.py`:
```python
class TestMyModule(unittest.TestCase):
    def setUp(self):
        self.module = MyModule()

    def test_lookup_returns_dict(self):
        result = self.module.lookup("example.com")
        self.assertIsInstance(result, dict)
        self.assertIn("target", result)
```

### 5 — Update docs

- Add row to the module table in `README.md`
- Add entry under `[Unreleased]` in `CHANGELOG.md`

---

## Code Style

```bash
# Format
black --line-length 100 .
isort --profile black --line-length 100 .

# Lint
flake8 . --max-line-length=100

# Type check (non-blocking)
mypy modules/ utils/ --ignore-missing-imports

# Security scan
bandit -r modules/ utils/ reporting/ main.py -ll
```

All of these run automatically in CI. PRs that fail lint will not be merged.

---

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(modules): add LinkedIn public profile scraper
fix(domain_intel): handle WHOIS timeout for .io domains
docs(readme): add LinkedIn module to table
refactor(helpers): extract retry logic to separate function
ci: add Python 3.12 to test matrix
```

---

## Pull Request Checklist

Before opening a PR, confirm:

- [ ] `pytest tests/ -v` passes locally
- [ ] `flake8` and `black --check` pass locally
- [ ] No real API keys or target data in any file
- [ ] `requirements.txt` updated if new libraries added
- [ ] `README.md` module table updated
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] PR description filled out completely
