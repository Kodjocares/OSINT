"""
modules/career_intel.py — Career & employment OSINT
Job postings, H-1B visa data, patent search, career history reconstruction
"""

import re
import logging
from typing import Dict, List
from utils.helpers import safe_request
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

H1B_API   = "https://h1bdata.info"
USPTO_API = "https://api.patentsview.org/patents/query"


class CareerIntel:
    """Career OSINT — job postings, visas, patents, salary data."""

    # ──────────────────────────────────────────────────────────
    # JOB POSTING SCRAPER
    # ──────────────────────────────────────────────────────────
    def scrape_job_postings(self, company: str) -> Dict:
        """Scrape public job postings to infer tech stack, org structure, headcount."""
        results = {"company": company, "jobs": [], "inferred_tech": [],
                   "inferred_roles": [], "signals": []}

        # Indeed via DDG
        ddg_resp = safe_request(
            f"https://html.duckduckgo.com/html/?q=site:indeed.com+\"{company}\" job"
        )
        if ddg_resp and ddg_resp.status_code == 200:
            soup = BeautifulSoup(ddg_resp.text, "lxml")
            for item in soup.find_all("div", class_="result")[:10]:
                a   = item.find("a", class_="result__a")
                snip = item.find("a", class_="result__snippet")
                if a:
                    results["jobs"].append({
                        "source":  "indeed",
                        "title":   a.get_text(strip=True),
                        "url":     a.get("href",""),
                        "snippet": snip.get_text(strip=True) if snip else "",
                    })

        # LinkedIn via DDG
        li_resp = safe_request(
            f"https://html.duckduckgo.com/html/?q=site:linkedin.com/jobs+\"{company}\""
        )
        if li_resp and li_resp.status_code == 200:
            soup = BeautifulSoup(li_resp.text, "lxml")
            for item in soup.find_all("div", class_="result")[:8]:
                a = item.find("a", class_="result__a")
                snip = item.find("a", class_="result__snippet")
                if a:
                    results["jobs"].append({
                        "source":  "linkedin",
                        "title":   a.get_text(strip=True),
                        "url":     a.get("href",""),
                        "snippet": snip.get_text(strip=True) if snip else "",
                    })

        # Analyze all snippets for intelligence
        all_text = " ".join(j.get("snippet","") + " " + j.get("title","")
                            for j in results["jobs"]).lower()

        tech_stack = [
            "python","java","golang","rust","node","react","angular","vue",
            "kubernetes","docker","aws","azure","gcp","terraform","ansible",
            "postgres","mysql","mongodb","redis","kafka","elasticsearch",
            "spark","hadoop","airflow","databricks","snowflake","dbt",
            "jenkins","github actions","gitlab ci","jira","confluence",
            "salesforce","servicenow","workday","sap","oracle",
        ]
        for kw in tech_stack:
            if kw in all_text:
                results["inferred_tech"].append(kw)

        role_patterns = [
            "engineer","developer","analyst","architect","manager",
            "director","vp","chief","intern","researcher","scientist",
        ]
        for role in role_patterns:
            if role in all_text:
                results["inferred_roles"].append(role)

        # Business signals
        if "remote" in all_text or "work from home" in all_text:
            results["signals"].append("Remote-friendly employer")
        if "series" in all_text or "startup" in all_text:
            results["signals"].append("Likely startup/scale-up")
        if "clearance" in all_text or "secret" in all_text:
            results["signals"].append("Government/defense contracts detected")
        if "visa" in all_text or "sponsorship" in all_text:
            results["signals"].append("Offers visa sponsorship")

        results["job_count"]     = len(results["jobs"])
        results["inferred_tech"] = sorted(set(results["inferred_tech"]))
        return results

    # ──────────────────────────────────────────────────────────
    # H-1B VISA DATA (public DOL PERM/LCA records)
    # ──────────────────────────────────────────────────────────
    def h1b_search(self, employer: str) -> Dict:
        """Search public H-1B LCA filing data for salary/job title information."""
        result = {"employer": employer, "filings": [], "note": ""}

        # H1BData.info (free public data aggregator)
        resp = safe_request(
            f"{H1B_API}/search",
            params={"employer": employer, "year": "2024,2023,2022",
                    "job": "", "city": ""}
        )
        if resp and resp.status_code == 200:
            try:
                soup = BeautifulSoup(resp.text, "lxml")
                for row in soup.find_all("tr")[1:21]:  # skip header
                    cells = row.find_all("td")
                    if len(cells) >= 6:
                        result["filings"].append({
                            "employer":  cells[0].get_text(strip=True),
                            "job_title": cells[1].get_text(strip=True),
                            "base_salary":cells[2].get_text(strip=True),
                            "location":  cells[3].get_text(strip=True),
                            "year":      cells[4].get_text(strip=True),
                        })
            except Exception:
                pass

        # Fallback: DDG search for public LCA data
        if not result["filings"]:
            resp2 = safe_request(
                f"https://html.duckduckgo.com/html/?q=h1b+lca+\"{employer}\" salary site:h1bdata.info"
            )
            if resp2 and resp2.status_code == 200:
                soup = BeautifulSoup(resp2.text, "lxml")
                for item in soup.find_all("div", class_="result")[:5]:
                    a = item.find("a", class_="result__a")
                    snip = item.find("a", class_="result__snippet")
                    if a:
                        result["filings"].append({
                            "source":  a.get_text(strip=True),
                            "url":     a.get("href",""),
                            "snippet": snip.get_text(strip=True) if snip else "",
                        })

        result["count"]  = len(result["filings"])
        result["h1b_url"] = f"https://h1bdata.info/index.php?em={employer}"
        return result

    # ──────────────────────────────────────────────────────────
    # PATENT SEARCH (USPTO PatentsView API — free)
    # ──────────────────────────────────────────────────────────
    def patent_search(self, inventor_or_assignee: str) -> Dict:
        """Search USPTO patents by inventor name or assignee company."""
        import json

        # Try as assignee first
        query = {"_or": [
            {"_text_all": {"patent_abstract": inventor_or_assignee}},
            {"assignee_organization": inventor_or_assignee},
        ]}

        resp = safe_request(
            USPTO_API,
            json_data={
                "q": query,
                "f": ["patent_number","patent_title","patent_date",
                      "assignee_organization","inventor_last_name",
                      "inventor_first_name","patent_abstract"],
                "o": {"per_page": 15},
            }
        )

        patents = []
        if resp and resp.status_code == 200:
            for p in resp.json().get("patents") or []:
                inventors = p.get("inventors") or []
                patents.append({
                    "number":    p.get("patent_number"),
                    "title":     p.get("patent_title"),
                    "date":      p.get("patent_date"),
                    "abstract":  (p.get("patent_abstract") or "")[:200],
                    "assignees": [a.get("assignee_organization") for a in (p.get("assignees") or [])],
                    "inventors": [f"{i.get('inventor_first_name','')} {i.get('inventor_last_name','')}" for i in inventors],
                    "url":       f"https://patents.google.com/patent/US{p.get('patent_number')}",
                })

        return {
            "query":   inventor_or_assignee,
            "patents": patents,
            "count":   len(patents),
            "note":    "USPTO public patent database — free, no key required",
        }

    # ──────────────────────────────────────────────────────────
    # WAYBACK JOB POSTINGS (historical job ads)
    # ──────────────────────────────────────────────────────────
    def historical_job_postings(self, company_domain: str) -> Dict:
        """Find deleted/archived job postings via Wayback Machine."""
        careers_urls = [
            f"https://{company_domain}/careers",
            f"https://{company_domain}/jobs",
            f"https://{company_domain}/work-with-us",
        ]
        results = {"domain": company_domain, "archived_postings": []}

        for url in careers_urls:
            wb_resp = safe_request(
                "http://web.archive.org/cdx/search/cdx",
                params={"url": url, "output": "json", "limit": 20,
                        "fl": "timestamp,original", "collapse": "timestamp:6"}
            )
            if wb_resp and wb_resp.status_code == 200:
                try:
                    rows = wb_resp.json()
                    if len(rows) > 1:
                        for row in rows[1:]:
                            results["archived_postings"].append({
                                "timestamp": row[0],
                                "url":       row[1],
                                "wayback":   f"https://web.archive.org/web/{row[0]}/{row[1]}",
                            })
                except Exception:
                    pass

        results["count"] = len(results["archived_postings"])
        return results

    # ──────────────────────────────────────────────────────────
    # FULL CAREER PROFILE
    # ──────────────────────────────────────────────────────────
    def full_career_profile(self, target: str, is_company: bool = True) -> Dict:
        if is_company:
            return {
                "target":     target,
                "type":       "company",
                "job_postings":    self.scrape_job_postings(target),
                "h1b_filings":    self.h1b_search(target),
                "patents":        self.patent_search(target),
                "archived_jobs":  self.historical_job_postings(target.lower().replace(" ","")+".com"),
            }
        return {
            "target":    target,
            "type":      "person",
            "patents":   self.patent_search(target),
        }
