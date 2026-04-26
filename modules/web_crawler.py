"""
modules/web_crawler.py — Website spider and content intelligence extractor
Crawl entire sites, extract all emails/phones/links, build sitemaps
"""

import re
import logging
from collections import deque
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set
from bs4 import BeautifulSoup
from utils.helpers import safe_request, clean_domain

logger = logging.getLogger(__name__)


class WebCrawler:
    """Recursively crawl a website and extract intelligence from all pages."""

    def __init__(self, max_pages: int = 50, max_depth: int = 3):
        self.max_pages = max_pages
        self.max_depth = max_depth

    # ──────────────────────────────────────────────────────────
    # MAIN CRAWL
    # ──────────────────────────────────────────────────────────
    def crawl(self, start_url: str) -> Dict:
        """Spider a website and extract all intelligence."""
        if not start_url.startswith("http"):
            start_url = f"https://{start_url}"

        parsed   = urlparse(start_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain   = parsed.netloc

        visited: Set[str]   = set()
        queue   = deque([(start_url, 0)])
        pages   = []

        # Aggregated findings
        all_emails:  Set[str] = set()
        all_phones:  Set[str] = set()
        all_ext_links: Set[str] = set()
        all_forms:   List[Dict] = []
        all_comments: List[str] = []
        login_pages: List[str] = []
        admin_pages: List[str] = []

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            resp = safe_request(url)
            if not resp or resp.status_code != 200:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            soup  = BeautifulSoup(resp.text, "lxml")
            text  = soup.get_text(separator=" ", strip=True)
            title = soup.title.string.strip() if soup.title else ""

            # Extract data from this page
            page_emails = set(re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", resp.text))
            page_phones = set(re.findall(
                r"[\+]?\d[\d\s\-\(\)\.]{7,}\d", text))
            all_emails.update(page_emails)
            all_phones.update(list(page_phones)[:5])

            # Forms (login/contact/search)
            forms = self._extract_forms(soup, url)
            all_forms.extend(forms)

            # HTML comments
            comments = re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL)
            all_comments.extend([c.strip()[:200] for c in comments if len(c.strip()) > 10])

            # Flag sensitive pages
            url_lower = url.lower()
            if any(k in url_lower for k in ["login", "signin", "auth", "sso"]):
                login_pages.append(url)
            if any(k in url_lower for k in ["admin", "dashboard", "panel", "manage", "wp-admin"]):
                admin_pages.append(url)

            # Collect internal + external links
            internal_links = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("#") or href.startswith("mailto:"):
                    continue
                full = urljoin(base_url, href)
                full_parsed = urlparse(full)
                if full_parsed.netloc == domain:
                    if full not in visited:
                        internal_links.append(full)
                        if depth + 1 <= self.max_depth:
                            queue.append((full, depth + 1))
                elif full.startswith("http"):
                    all_ext_links.add(full)

            pages.append({
                "url":        url,
                "title":      title,
                "depth":      depth,
                "status":     resp.status_code,
                "emails":     list(page_emails),
                "phones":     list(page_phones)[:3],
                "forms":      len(forms),
                "links_out":  len(internal_links),
                "word_count": len(text.split()),
                "has_login":  url in login_pages,
                "has_admin":  url in admin_pages,
            })

        # Technology hints from aggregated data
        technologies = self._detect_technologies_from_pages(pages)

        return {
            "start_url":       start_url,
            "domain":          domain,
            "pages_crawled":   len(pages),
            "emails_found":    sorted(all_emails),
            "phones_found":    sorted(all_phones)[:20],
            "login_pages":     login_pages,
            "admin_pages":     admin_pages,
            "external_links":  sorted(all_ext_links)[:30],
            "forms_found":     all_forms[:20],
            "html_comments":   all_comments[:20],
            "technologies":    technologies,
            "sitemap":         [p["url"] for p in pages],
            "pages":           pages,
        }

    # ──────────────────────────────────────────────────────────
    # EXTRACT FORMS
    # ──────────────────────────────────────────────────────────
    def _extract_forms(self, soup: "BeautifulSoup", page_url: str) -> List[Dict]:
        forms = []
        for form in soup.find_all("form"):
            inputs = [
                {"name": i.get("name"), "type": i.get("type"), "id": i.get("id")}
                for i in form.find_all("input")
            ]
            # Classify form purpose
            form_text = str(form).lower()
            purpose = "unknown"
            if any(k in form_text for k in ["password", "passwd"]):
                purpose = "login/auth"
            elif any(k in form_text for k in ["search", "query", "q="]):
                purpose = "search"
            elif any(k in form_text for k in ["email", "contact", "message"]):
                purpose = "contact"
            elif any(k in form_text for k in ["register", "signup", "create"]):
                purpose = "registration"

            forms.append({
                "page":   page_url,
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "purpose":purpose,
                "inputs": inputs,
            })
        return forms

    # ──────────────────────────────────────────────────────────
    # QUICK PAGE SCRAPE (single page, no crawl)
    # ──────────────────────────────────────────────────────────
    def scrape_page(self, url: str) -> Dict:
        """Extract all intelligence from a single page without crawling."""
        if not url.startswith("http"):
            url = f"https://{url}"
        resp = safe_request(url)
        if not resp or resp.status_code != 200:
            return {"url": url, "error": "Page unavailable"}

        soup = BeautifulSoup(resp.text, "lxml")
        text = soup.get_text(separator=" ", strip=True)

        return {
            "url":       url,
            "title":     soup.title.string.strip() if soup.title else None,
            "emails":    list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", resp.text))),
            "phones":    list(set(re.findall(r"[\+]?\d[\d\s\-\(\)\.]{7,}\d", text)))[:10],
            "links":     list(set(a["href"] for a in soup.find_all("a", href=True)
                               if a["href"].startswith("http")))[:30],
            "images":    [img["src"] for img in soup.find_all("img", src=True)
                          if img["src"].startswith("http")][:20],
            "comments":  [c[:200] for c in re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL)
                          if len(c.strip()) > 10][:10],
            "forms":     self._extract_forms(soup, url),
            "headers":   dict(resp.headers),
            "word_count":len(text.split()),
        }

    def _detect_technologies_from_pages(self, pages: List[Dict]) -> List[str]:
        """Detect technologies from page patterns."""
        # This would normally check headers/content; simplified version
        return []
