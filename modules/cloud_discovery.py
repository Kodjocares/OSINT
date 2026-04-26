"""
modules/cloud_discovery.py — Cloud asset discovery
S3 buckets, Azure Blob, GCP Storage, Firebase exposure checks
"""

import re
import logging
from typing import Dict, List
from utils.helpers import safe_request, clean_domain

logger = logging.getLogger(__name__)


class CloudDiscovery:
    """Enumerate exposed cloud storage assets for a target domain/company."""

    # ──────────────────────────────────────────────────────────
    # AMAZON S3
    # ──────────────────────────────────────────────────────────
    def enumerate_s3_buckets(self, target: str) -> Dict:
        """Generate and test S3 bucket name permutations."""
        base = clean_domain(target).split(".")[0].lower().replace("-", "")
        permutations = self._generate_bucket_names(base)
        found, not_found, errors = [], [], []

        for bucket in permutations:
            url1 = f"https://{bucket}.s3.amazonaws.com"
            url2 = f"https://s3.amazonaws.com/{bucket}"
            for url in [url1, url2]:
                resp = safe_request(url, allow_redirects=False)
                if resp is None:
                    errors.append(bucket)
                    break
                if resp.status_code == 200:
                    # Check if listing is enabled
                    listing = "<ListBucketResult" in resp.text
                    found.append({
                        "bucket":  bucket,
                        "url":     url,
                        "public":  True,
                        "listing": listing,
                        "risk":    "CRITICAL — Public listing" if listing else "HIGH — Public read",
                        "files_preview": self._extract_s3_files(resp.text) if listing else [],
                    })
                    break
                elif resp.status_code in (403, 405):
                    found.append({
                        "bucket": bucket, "url": url,
                        "public": False,
                        "risk":   "INFO — Bucket exists but access denied",
                    })
                    break
                elif resp.status_code == 404:
                    not_found.append(bucket)
                    break

        return {
            "target":       target,
            "permutations_tested": len(permutations),
            "buckets_found":  found,
            "buckets_exist":  len(found),
            "risk_level":    "CRITICAL" if any(f.get("listing") for f in found) else
                             "HIGH" if found else "LOW",
        }

    def _extract_s3_files(self, xml_text: str) -> List[str]:
        return re.findall(r"<Key>([^<]+)</Key>", xml_text)[:20]

    def _generate_bucket_names(self, base: str) -> List[str]:
        suffixes = [
            "", "-dev", "-staging", "-prod", "-backup", "-data",
            "-assets", "-media", "-static", "-files", "-public",
            "-private", "-internal", "-logs", "-archive", "-uploads",
            "-images", "-videos", "-documents", "-reports", "-config",
            "-secrets", "-api", "-web", "-app", "-test", "-uat",
        ]
        prefixes = ["", "dev-", "staging-", "prod-", "backup-", "data-"]
        names = set()
        for suf in suffixes:
            names.add(f"{base}{suf}")
        for pre in prefixes:
            names.add(f"{pre}{base}")
        return list(names)

    # ──────────────────────────────────────────────────────────
    # AZURE BLOB STORAGE
    # ──────────────────────────────────────────────────────────
    def enumerate_azure_blobs(self, target: str) -> Dict:
        """Check for exposed Azure Blob Storage containers."""
        base = clean_domain(target).split(".")[0].lower().replace("-", "")
        found, tested = [], 0

        for name in self._generate_bucket_names(base)[:30]:
            url = f"https://{name}.blob.core.windows.net"
            resp = safe_request(url, allow_redirects=False)
            tested += 1
            if resp and resp.status_code in (200, 400, 409):
                found.append({
                    "account":    name,
                    "url":        url,
                    "status":     resp.status_code,
                    "accessible": resp.status_code == 200,
                })

        return {
            "target":  target,
            "tested":  tested,
            "found":   found,
            "count":   len(found),
        }

    # ──────────────────────────────────────────────────────────
    # GOOGLE CLOUD STORAGE
    # ──────────────────────────────────────────────────────────
    def enumerate_gcs_buckets(self, target: str) -> Dict:
        """Check for exposed GCP Cloud Storage buckets."""
        base = clean_domain(target).split(".")[0].lower().replace("-", "")
        found, tested = [], 0

        for name in self._generate_bucket_names(base)[:25]:
            url = f"https://storage.googleapis.com/{name}"
            resp = safe_request(url, allow_redirects=False)
            tested += 1
            if resp and resp.status_code == 200:
                listing = "<ListBucketResult" in resp.text
                found.append({
                    "bucket":  name,
                    "url":     url,
                    "public":  True,
                    "listing": listing,
                    "risk":    "CRITICAL" if listing else "HIGH",
                })
            elif resp and resp.status_code == 403:
                found.append({"bucket": name, "url": url, "public": False, "risk": "INFO"})

        return {"target": target, "tested": tested, "found": found, "count": len(found)}

    # ──────────────────────────────────────────────────────────
    # FIREBASE
    # ──────────────────────────────────────────────────────────
    def check_firebase(self, target: str) -> Dict:
        """Check for exposed Firebase Realtime Databases."""
        base = clean_domain(target).split(".")[0].lower().replace("-", "")
        names = [base, f"{base}-default-rtdb", f"{base}-prod", f"{base}-dev"]
        found = []

        for name in names:
            url = f"https://{name}.firebaseio.com/.json"
            resp = safe_request(url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    found.append({
                        "url":         url,
                        "accessible":  True,
                        "data_preview":str(data)[:200] if data else "null",
                        "risk":        "CRITICAL — Database publicly readable",
                    })
                except Exception:
                    found.append({"url": url, "accessible": True, "risk": "HIGH"})
            elif resp and resp.status_code == 401:
                found.append({"url": url, "accessible": False, "risk": "INFO — Auth required"})

        return {"target": target, "firebase_results": found, "exposed": len(
            [f for f in found if f.get("accessible")]
        )}

    # ──────────────────────────────────────────────────────────
    # FULL CLOUD SCAN
    # ──────────────────────────────────────────────────────────
    def full_cloud_scan(self, target: str) -> Dict:
        """Run all cloud storage enumeration checks."""
        return {
            "target":   target,
            "s3":       self.enumerate_s3_buckets(target),
            "azure":    self.enumerate_azure_blobs(target),
            "gcs":      self.enumerate_gcs_buckets(target),
            "firebase": self.check_firebase(target),
        }
