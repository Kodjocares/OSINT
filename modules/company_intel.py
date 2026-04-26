"""
modules/company_intel.py — Corporate OSINT: business registrations, filings, structure
Uses OpenCorporates, SEC EDGAR, and web scraping of public business records
"""

import re
import logging
from typing import Dict, List
from bs4 import BeautifulSoup
from utils.helpers import safe_request, clean_domain

logger = logging.getLogger(__name__)

OC_API    = "https://api.opencorporates.com/v0.4"
EDGAR_API = "https://efts.sec.gov/LATEST/search-index"
EDGAR_FTS = "https://efts.sec.gov/LATEST/search-index?q="


class CompanyIntel:
    """Corporate OSINT — registrations, officers, filings, subsidiaries."""

    # ──────────────────────────────────────────────────────────
    # OPENCORPORATES — company search
    # ──────────────────────────────────────────────────────────
    def search_company(self, company_name: str, jurisdiction: str = None) -> Dict:
        """Search OpenCorporates for company registrations."""
        params = {
            "q":                company_name,
            "format":           "json",
            "per_page":         10,
        }
        if jurisdiction:
            params["jurisdiction_code"] = jurisdiction

        resp = safe_request(f"{OC_API}/companies/search", params=params)
        if not resp or resp.status_code != 200:
            return {"error": "OpenCorporates unavailable", "query": company_name}

        companies = []
        for item in resp.json().get("results", {}).get("companies", []):
            c = item.get("company", {})
            companies.append({
                "name":             c.get("name"),
                "jurisdiction":     c.get("jurisdiction_code"),
                "company_number":   c.get("company_number"),
                "status":           c.get("current_status"),
                "incorporation_date": c.get("incorporation_date"),
                "dissolution_date": c.get("dissolution_date"),
                "company_type":     c.get("company_type"),
                "registered_address": c.get("registered_address", {}).get("in_full"),
                "opencorporates_url": c.get("opencorporates_url"),
                "source":           c.get("source", {}).get("publisher"),
            })

        return {"query": company_name, "results": companies, "count": len(companies)}

    def get_company_officers(self, company_number: str, jurisdiction: str) -> Dict:
        """Get directors and officers for a company."""
        resp = safe_request(
            f"{OC_API}/companies/{jurisdiction}/{company_number}/officers",
            params={"format": "json", "per_page": 50}
        )
        if not resp or resp.status_code != 200:
            return {"error": "Could not retrieve officers"}

        officers = []
        for item in resp.json().get("results", {}).get("officers", []):
            o = item.get("officer", {})
            officers.append({
                "name":       o.get("name"),
                "position":   o.get("position"),
                "start_date": o.get("start_date"),
                "end_date":   o.get("end_date"),
                "nationality":o.get("nationality"),
                "occupation": o.get("occupation"),
            })
        return {"company": company_number, "jurisdiction": jurisdiction,
                "officers": officers, "count": len(officers)}

    # ──────────────────────────────────────────────────────────
    # SEC EDGAR — US public company filings
    # ──────────────────────────────────────────────────────────
    def sec_edgar_search(self, company_name: str) -> Dict:
        """Search SEC EDGAR for public company filings."""
        resp = safe_request(
            "https://efts.sec.gov/LATEST/search-index",
            params={
                "q":           f'"{company_name}"',
                "dateRange":   "custom",
                "startdt":     "2020-01-01",
                "forms":       "10-K,10-Q,8-K,DEF 14A",
            }
        )
        results = []
        if resp and resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            for h in hits[:10]:
                src = h.get("_source", {})
                results.append({
                    "entity_name":  src.get("entity_name"),
                    "file_date":    src.get("file_date"),
                    "form_type":    src.get("form_type"),
                    "description":  src.get("file_description"),
                    "cik":          src.get("entity_id"),
                    "url":          f"https://www.sec.gov/Archives/edgar/data/{src.get('entity_id','')}/"
                })

        # Also try EDGAR full-text search
        resp2 = safe_request(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": company_name, "dateRange": "custom",
                    "startdt": "2023-01-01", "enddt": "2025-12-31"}
        )
        return {"company": company_name, "filings": results, "count": len(results)}

    def get_company_cik(self, company_name: str) -> Dict:
        """Look up SEC CIK number for a company."""
        resp = safe_request(
            "https://www.sec.gov/cgi-bin/browse-edgar",
            params={
                "company":  company_name,
                "CIK":      "",
                "type":     "10-K",
                "dateb":    "",
                "owner":    "include",
                "count":    "10",
                "search_text": "",
                "action":   "getcompany",
            }
        )
        ciks = []
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            for row in soup.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 2:
                    cik_link = row.find("a", href=re.compile(r"CIK="))
                    if cik_link:
                        cik = re.search(r"CIK=(\d+)", cik_link.get("href", ""))
                        ciks.append({
                            "name": cells[0].get_text(strip=True),
                            "cik":  cik.group(1) if cik else None,
                            "url":  f"https://www.sec.gov{cik_link.get('href','')}",
                        })
        return {"query": company_name, "results": ciks}

    # ──────────────────────────────────────────────────────────
    # LINKEDIN JOB POSTINGS — tech stack & org insight
    # ──────────────────────────────────────────────────────────
    def scrape_linkedin_jobs(self, company_name: str) -> Dict:
        """Scrape public LinkedIn job postings to infer tech stack & org structure."""
        search_url = (f"https://html.duckduckgo.com/html/?q="
                      f"site:linkedin.com/jobs \"{company_name}\" job posting")
        resp = safe_request(search_url)
        jobs = []
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            for item in soup.find_all("div", class_="result")[:10]:
                title = item.find("a", class_="result__a")
                snippet = item.find("a", class_="result__snippet")
                if title:
                    jobs.append({
                        "title":   title.get_text(strip=True),
                        "url":     title.get("href", ""),
                        "snippet": snippet.get_text(strip=True) if snippet else "",
                    })
        # Extract tech keywords from job snippets
        tech_keywords = set()
        all_text = " ".join(j.get("snippet", "") for j in jobs).lower()
        tech_stack_patterns = [
            "python","java","golang","rust","node","react","angular","kubernetes",
            "docker","aws","azure","gcp","terraform","postgres","mysql","mongodb",
            "redis","kafka","elasticsearch","jenkins","gitlab","jira","salesforce",
        ]
        for kw in tech_stack_patterns:
            if kw in all_text:
                tech_keywords.add(kw)

        return {
            "company":       company_name,
            "jobs_found":    len(jobs),
            "jobs":          jobs,
            "inferred_tech": sorted(tech_keywords),
        }

    # ──────────────────────────────────────────────────────────
    # FULL COMPANY PROFILE
    # ──────────────────────────────────────────────────────────
    def full_company_profile(self, company_name: str) -> Dict:
        return {
            "company":        company_name,
            "registrations":  self.search_company(company_name),
            "sec_filings":    self.sec_edgar_search(company_name),
            "job_postings":   self.scrape_linkedin_jobs(company_name),
        }
