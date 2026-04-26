"""
modules/breach_check.py — Data breach lookups and password exposure checks
Uses HaveIBeenPwned API (k-anonymity model — passwords are NEVER sent in plain text)
"""

import hashlib
import logging
from typing import Dict, List
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

class BreachCheck:
    """
    Check emails against HaveIBeenPwned breach database.
    Check passwords using k-anonymity — only the first 5 chars of the SHA-1
    hash are sent to the API; the full hash never leaves your machine.
    """

    HIBP_BREACH_URL  = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
    HIBP_PASTE_URL   = "https://haveibeenpwned.com/api/v3/pasteaccount/{account}"
    HIBP_PWNED_URL   = "https://api.pwnedpasswords.com/range/{prefix}"
    HIBP_BREACHES_URL= "https://haveibeenpwned.com/api/v3/breaches"

    def __init__(self, hibp_api_key: str = ""):
        self.hibp_key = hibp_api_key

    def _hibp_headers(self) -> Dict:
        h = {
            "hibp-api-key": self.hibp_key,
            "user-agent":   "OSINT-Research-Tool/1.0",
        }
        if not self.hibp_key:
            del h["hibp-api-key"]
        return h

    # ─────────────────────────────────────────────
    # EMAIL BREACH CHECK
    # ─────────────────────────────────────────────
    def check_email(self, email: str) -> Dict:
        """Check if an email appears in known data breaches."""
        result = {
            "email":    email,
            "breaches": [],
            "pastes":   [],
            "breach_count": 0,
            "paste_count":  0,
        }

        # Breaches
        resp = safe_request(
            self.HIBP_BREACH_URL.format(account=email),
            headers={**self._hibp_headers(), "Accept": "application/json"},
            params={"truncateResponse": "false"},
        )
        if resp and resp.status_code == 200:
            breaches = resp.json()
            result["breaches"] = [
                {
                    "name":         b.get("Name"),
                    "domain":       b.get("Domain"),
                    "breach_date":  b.get("BreachDate"),
                    "added_date":   b.get("AddedDate"),
                    "pwn_count":    b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "is_verified":  b.get("IsVerified"),
                    "is_sensitive": b.get("IsSensitive"),
                    "description":  b.get("Description", "")[:200],
                }
                for b in breaches
            ]
            result["breach_count"] = len(breaches)
        elif resp and resp.status_code == 404:
            result["breaches"] = []
            result["breach_count"] = 0

        # Pastes
        paste_resp = safe_request(
            self.HIBP_PASTE_URL.format(account=email),
            headers={**self._hibp_headers(), "Accept": "application/json"},
        )
        if paste_resp and paste_resp.status_code == 200:
            pastes = paste_resp.json()
            result["pastes"] = [
                {
                    "source":     p.get("Source"),
                    "id":         p.get("Id"),
                    "title":      p.get("Title"),
                    "date":       p.get("Date"),
                    "email_count":p.get("EmailCount"),
                }
                for p in pastes
            ]
            result["paste_count"] = len(pastes)

        result["at_risk"] = result["breach_count"] > 0 or result["paste_count"] > 0
        return result

    # ─────────────────────────────────────────────
    # PASSWORD EXPOSURE CHECK (k-anonymity)
    # ─────────────────────────────────────────────
    def check_password(self, password: str) -> Dict:
        """
        Check if a password has appeared in known data breaches.
        Uses k-anonymity: only the first 5 characters of the SHA-1 hash
        are sent to the HIBP API — the actual password is NEVER transmitted.
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        result = {
            "sha1_prefix":  prefix,
            "exposed":      False,
            "times_seen":   0,
            "risk_level":   "Unknown",
            "note":         "Password hash checked via k-anonymity. Plain text was never sent.",
        }

        resp = safe_request(self.HIBP_PWNED_URL.format(prefix=prefix))
        if not resp or resp.status_code != 200:
            result["error"] = "Could not contact HIBP password API"
            return result

        hashes = resp.text.splitlines()
        for line in hashes:
            parts = line.split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                count = int(parts[1])
                result["exposed"]    = True
                result["times_seen"] = count
                if count > 100000:
                    result["risk_level"] = "CRITICAL — Extremely common password"
                elif count > 10000:
                    result["risk_level"] = "HIGH — Widely seen in breaches"
                elif count > 1000:
                    result["risk_level"] = "MEDIUM — Seen multiple times in breaches"
                else:
                    result["risk_level"] = "LOW — Seen in breach data"
                break

        if not result["exposed"]:
            result["risk_level"] = "SAFE — Not found in known breach databases"

        return result

    # ─────────────────────────────────────────────
    # BULK EMAIL CHECK
    # ─────────────────────────────────────────────
    def bulk_check_emails(self, emails: List[str]) -> List[Dict]:
        """Check multiple emails against breach databases."""
        return [self.check_email(email) for email in emails]

    # ─────────────────────────────────────────────
    # LIST ALL KNOWN BREACHES
    # ─────────────────────────────────────────────
    def list_all_breaches(self, domain: str = None) -> List[Dict]:
        """Return all known breach datasets, optionally filtered by domain."""
        params = {}
        if domain:
            params["domain"] = domain
        resp = safe_request(
            self.HIBP_BREACHES_URL,
            headers={**self._hibp_headers(), "Accept": "application/json"},
            params=params or None,
        )
        if resp and resp.status_code == 200:
            breaches = resp.json()
            return [
                {
                    "name":        b.get("Name"),
                    "domain":      b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count":   b.get("PwnCount"),
                    "data_classes":b.get("DataClasses", []),
                    "is_sensitive":b.get("IsSensitive"),
                }
                for b in breaches
            ]
        return []
