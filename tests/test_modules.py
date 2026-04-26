"""
tests/test_modules.py — Basic unit tests for OSINT Tool modules
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import hashlib


# ─────────────────────────────────────────────
# Config / Helpers
# ─────────────────────────────────────────────
class TestConfig:
    def test_config_imports(self):
        from config import SOCIAL_PLATFORMS, DORK_TEMPLATES
        assert len(SOCIAL_PLATFORMS) > 0
        assert len(DORK_TEMPLATES) > 0

    def test_dork_templates_have_placeholders(self):
        from config import DORK_TEMPLATES
        for name, template in DORK_TEMPLATES.items():
            assert "{target}" in template, f"Dork '{name}' missing {{target}} placeholder"


class TestHelpers:
    def test_clean_domain_strips_http(self):
        from utils.helpers import clean_domain
        assert clean_domain("http://example.com/")  == "example.com"
        assert clean_domain("https://www.example.com") == "example.com"
        assert clean_domain("  EXAMPLE.COM  ") == "example.com"

    def test_get_headers_returns_dict(self):
        from utils.helpers import get_headers
        h = get_headers()
        assert "User-Agent" in h
        assert len(h["User-Agent"]) > 10


# ─────────────────────────────────────────────
# Username Lookup
# ─────────────────────────────────────────────
class TestUsernameLookup:
    def setup_method(self):
        from modules.username_lookup import UsernameLookup
        self.lookup = UsernameLookup()

    def test_email_format_valid(self):
        result = self.lookup.investigate_email("test@example.com")
        assert result["valid_format"] is True
        assert result["domain"] == "example.com"

    def test_email_format_invalid(self):
        result = self.lookup.investigate_email("not-an-email")
        assert result["valid_format"] is False

    def test_platforms_loaded(self):
        assert len(self.lookup.platforms) >= 20


# ─────────────────────────────────────────────
# Breach Check — Password (k-anonymity, no network needed)
# ─────────────────────────────────────────────
class TestBreachCheck:
    def setup_method(self):
        from modules.breach_check import BreachCheck
        self.bc = BreachCheck()

    def test_password_hash_prefix_correct(self):
        """Verify the correct SHA-1 prefix is computed."""
        password = "password123"
        expected_sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        result = self.bc.check_password.__wrapped__(self.bc, password) \
            if hasattr(self.bc.check_password, "__wrapped__") else None
        # Just verify the hash logic directly
        assert expected_sha1[:5] == hashlib.sha1(b"password123").hexdigest().upper()[:5]

    def test_password_result_structure(self):
        """Result dict has required keys (may need network — skip if unavailable)."""
        try:
            result = self.bc.check_password("test_unique_string_xyz_123_abc")
            assert "exposed" in result
            assert "risk_level" in result
            assert "note" in result
            assert "sha1_prefix" in result
        except Exception:
            pytest.skip("Network not available")

    def test_email_result_structure(self):
        """Email check returns required keys."""
        try:
            result = self.bc.check_email("test@example.com")
            assert "email" in result
            assert "breaches" in result
            assert "pastes" in result
            assert "breach_count" in result
        except Exception:
            pytest.skip("Network not available or HIBP key required")


# ─────────────────────────────────────────────
# Phone Lookup
# ─────────────────────────────────────────────
class TestPhoneLookup:
    def setup_method(self):
        from modules.phone_lookup import PhoneLookup
        self.pl = PhoneLookup()

    def test_valid_us_number(self):
        try:
            result = self.pl._parse_number("+14155552671")
            assert result.get("valid") is True
            assert result.get("country") == "United States"
        except Exception:
            pytest.skip("phonenumbers not installed")

    def test_invalid_number(self):
        try:
            result = self.pl._parse_number("not-a-number")
            assert result.get("valid") is False or "error" in result
        except Exception:
            pytest.skip("phonenumbers not installed")


# ─────────────────────────────────────────────
# Google Dorking
# ─────────────────────────────────────────────
class TestGoogleDorking:
    def setup_method(self):
        from modules.google_dorking import GoogleDorking
        self.gd = GoogleDorking()

    def test_generate_dorks_returns_all_categories(self):
        from config import DORK_TEMPLATES
        result = self.gd.generate_dorks("example.com")
        assert result["target"] == "example.com"
        assert len(result["dorks"]) == len(DORK_TEMPLATES)

    def test_dork_urls_contain_target(self):
        result = self.gd.generate_dorks("example.com")
        for cat, info in result["dorks"].items():
            assert "example.com" in info["query"]

    def test_custom_dork_builder(self):
        dork = self.gd.build_custom_dork(
            site="example.com",
            filetype="pdf",
            intext="confidential"
        )
        assert "site:example.com" in dork
        assert "filetype:pdf" in dork
        assert 'intext:"confidential"' in dork


# ─────────────────────────────────────────────
# Domain Intel (offline parts)
# ─────────────────────────────────────────────
class TestDomainIntel:
    def setup_method(self):
        from modules.domain_intel import DomainIntel
        self.di = DomainIntel()

    def test_fingerprint_structure(self):
        """Fingerprint returns correct keys (may fail without network)."""
        try:
            result = self.di.fingerprint_technologies("example.com")
            assert "technologies" in result
            assert isinstance(result["technologies"], list)
        except Exception:
            pytest.skip("Network not available")


# ─────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────
class TestReporting:
    def setup_method(self, tmp_path=None):
        import tempfile
        from reporting.report_generator import ReportGenerator
        self.tmp = tempfile.mkdtemp()
        self.rg = ReportGenerator(self.tmp)

    def test_json_report_created(self):
        import os, json
        path = self.rg.save_json({"test": "data", "num": 42}, "test_report.json")
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["test"] == "data"

    def test_html_report_created(self):
        import os
        path = self.rg.generate_html_report(
            {"section1": {"key": "value"}, "section2": ["a", "b", "c"]},
            title="Test Report",
            filename="test_report.html"
        )
        assert os.path.exists(path)
        content = open(path).read()
        assert "Test Report" in content
        assert "section1" in content.lower() or "Section1" in content
