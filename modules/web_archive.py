"""
modules/web_archive.py — Wayback Machine / Web Archive intelligence
Query historical snapshots, extract old content, compare changes
"""

import re
import logging
from typing import Dict, List, Optional
from datetime import datetime
from utils.helpers import safe_request, clean_domain

logger = logging.getLogger(__name__)

CDX_API   = "http://web.archive.org/cdx/search/cdx"
AVAIL_API = "https://archive.org/wayback/available"
WB_BASE   = "https://web.archive.org/web"


class WebArchive:
    """Wayback Machine OSINT — historical snapshots, deleted content, timeline."""

    # ──────────────────────────────────────────────────────────
    # AVAILABILITY CHECK
    # ──────────────────────────────────────────────────────────
    def check_availability(self, url: str) -> Dict:
        resp = safe_request(AVAIL_API, params={"url": url})
        if resp and resp.status_code == 200:
            data = resp.json()
            snap = data.get("archived_snapshots", {}).get("closest", {})
            return {
                "url":       url,
                "available": snap.get("available", False),
                "timestamp": snap.get("timestamp"),
                "snapshot":  snap.get("url"),
                "status":    snap.get("status"),
            }
        return {"url": url, "error": "Archive API unavailable"}

    # ──────────────────────────────────────────────────────────
    # FULL SNAPSHOT HISTORY
    # ──────────────────────────────────────────────────────────
    def get_snapshot_history(self, url: str, limit: int = 50) -> Dict:
        """Retrieve all archived snapshots for a URL."""
        params = {
            "url":      url,
            "output":   "json",
            "fl":       "timestamp,statuscode,mimetype,length",
            "limit":    limit,
            "collapse": "timestamp:8",  # one per day
        }
        resp = safe_request(CDX_API, params=params)
        snapshots = []
        if resp and resp.status_code == 200:
            try:
                rows = resp.json()
                if len(rows) > 1:
                    headers = rows[0]
                    for row in rows[1:]:
                        entry = dict(zip(headers, row))
                        ts = entry.get("timestamp", "")
                        if len(ts) >= 14:
                            entry["datetime"] = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]}"
                        entry["wayback_url"] = f"{WB_BASE}/{ts}/{url}"
                        snapshots.append(entry)
            except Exception as e:
                logger.warning(f"[ARCHIVE] Parse error: {e}")

        return {
            "url":            url,
            "snapshot_count": len(snapshots),
            "first_seen":     snapshots[0].get("datetime") if snapshots else None,
            "last_seen":      snapshots[-1].get("datetime") if snapshots else None,
            "snapshots":      snapshots,
        }

    # ──────────────────────────────────────────────────────────
    # EXTRACT CONTENT FROM SNAPSHOT
    # ──────────────────────────────────────────────────────────
    def extract_snapshot_content(self, url: str, timestamp: str = None) -> Dict:
        """Download a snapshot and extract emails, phone numbers, names, links."""
        from bs4 import BeautifulSoup

        if timestamp:
            wayback_url = f"{WB_BASE}/{timestamp}/{url}"
        else:
            avail = self.check_availability(url)
            wayback_url = avail.get("snapshot")
            if not wayback_url:
                return {"error": "No snapshot available", "url": url}

        resp = safe_request(wayback_url)
        if not resp or resp.status_code != 200:
            return {"error": "Could not retrieve snapshot", "wayback_url": wayback_url}

        soup = BeautifulSoup(resp.text, "lxml")

        # Strip Wayback Machine toolbar
        for tag in soup.find_all(id="wm-ipp-base"):
            tag.decompose()

        text = soup.get_text(separator=" ", strip=True)

        emails  = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)))
        phones  = list(set(re.findall(r"[\+]?\d[\d\s\-\(\)]{7,}\d", text)))[:15]
        links   = list(set(a["href"] for a in soup.find_all("a", href=True)
                           if a["href"].startswith("http") and "web.archive.org" not in a["href"]))[:30]

        # Meta data
        metas = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property", "")
            if name and tag.get("content"):
                metas[name] = tag["content"]

        return {
            "wayback_url": wayback_url,
            "source_url":  url,
            "title":       soup.title.string.strip() if soup.title else None,
            "meta":        metas,
            "emails":      emails,
            "phones":      phones,
            "links":       links,
            "word_count":  len(text.split()),
            "text_preview": text[:500],
        }

    # ──────────────────────────────────────────────────────────
    # DOMAIN TIMELINE
    # ──────────────────────────────────────────────────────────
    def domain_timeline(self, domain: str) -> Dict:
        """Build a timeline of a domain's web presence."""
        domain = clean_domain(domain)
        history = self.get_snapshot_history(f"http://{domain}", limit=200)

        # Yearly breakdown
        yearly: Dict[str, int] = {}
        for snap in history.get("snapshots", []):
            year = snap.get("timestamp", "????")[:4]
            yearly[year] = yearly.get(year, 0) + 1

        # HTTP status breakdown
        status_counts: Dict[str, int] = {}
        for snap in history.get("snapshots", []):
            sc = snap.get("statuscode", "unknown")
            status_counts[sc] = status_counts.get(sc, 0) + 1

        return {
            "domain":         domain,
            "first_seen":     history.get("first_seen"),
            "last_seen":      history.get("last_seen"),
            "total_snapshots":history.get("snapshot_count"),
            "yearly_counts":  yearly,
            "status_breakdown": status_counts,
            "snapshots_sample": history.get("snapshots", [])[:10],
        }

    # ──────────────────────────────────────────────────────────
    # COMPARE SNAPSHOTS
    # ──────────────────────────────────────────────────────────
    def compare_snapshots(self, url: str, ts1: str, ts2: str) -> Dict:
        """Compare content between two snapshots."""
        s1 = self.extract_snapshot_content(url, ts1)
        s2 = self.extract_snapshot_content(url, ts2)

        old_emails = set(s1.get("emails", []))
        new_emails = set(s2.get("emails", []))
        old_links  = set(s1.get("links", []))
        new_links  = set(s2.get("links", []))

        return {
            "url": url,
            "snapshot_1": ts1,
            "snapshot_2": ts2,
            "emails_added":   list(new_emails - old_emails),
            "emails_removed": list(old_emails - new_emails),
            "links_added":    list(new_links  - old_links),
            "links_removed":  list(old_links  - new_links),
            "title_changed":  s1.get("title") != s2.get("title"),
            "old_title":      s1.get("title"),
            "new_title":      s2.get("title"),
        }
