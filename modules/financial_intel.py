"""
modules/financial_intel.py — Financial OSINT
SEC filings, OFAC sanctions, Panama Papers/ICIJ, insider trading,
OpenCorporates beneficial ownership, FinCEN patterns
"""

import re
import logging
from typing import Dict, List
from utils.helpers import safe_request
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

OFAC_API    = "https://api.ofac-api.com/v4/search"
ICIJ_API    = "https://offshoreleaks.icij.org/api"
SEC_API     = "https://efts.sec.gov/LATEST/search-index"
SEC_EDGAR   = "https://data.sec.gov"


class FinancialIntel:
    """Financial OSINT — sanctions, leaks, filings, beneficial ownership."""

    # ──────────────────────────────────────────────────────────
    # OFAC SANCTIONS CHECK
    # ──────────────────────────────────────────────────────────
    def ofac_check(self, name: str) -> Dict:
        """
        Check if a person/entity appears on OFAC sanctions lists.
        Uses free OFAC search API.
        """
        # Primary: OFAC SDN list via Treasury API
        result = {"query": name, "sanctioned": False, "matches": [], "lists_checked": []}

        # Try opensanctions.org (free public API)
        resp = safe_request(
            "https://api.opensanctions.org/match/sanctions",
            json_data={
                "queries": {
                    "q1": {
                        "schema": "Thing",
                        "properties": {"name": [name]},
                    }
                }
            },
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            for qid, res in data.get("responses", {}).items():
                for m in res.get("results", []):
                    score = m.get("score", 0)
                    if score > 0.6:
                        result["sanctioned"] = True
                        result["matches"].append({
                            "name":      m.get("caption"),
                            "score":     score,
                            "datasets":  m.get("datasets", []),
                            "countries": m.get("properties", {}).get("country", []),
                            "type":      m.get("schema"),
                            "id":        m.get("id"),
                        })
            result["lists_checked"].append("OpenSanctions consolidated database")

        # US Treasury OFAC SDN list (direct XML check via web scrape)
        resp2 = safe_request(
            "https://sanctionsearch.ofac.treas.gov/api/search",
            params={"searchtype": "1", "p": "1", "s": "1", "name": name},
        )
        if resp2 and resp2.status_code == 200:
            try:
                data = resp2.json()
                entries = data.get("sdnList", {}).get("sdnEntry", [])
                if not isinstance(entries, list):
                    entries = [entries]
                for e in entries[:5]:
                    result["sanctioned"] = True
                    result["matches"].append({
                        "name":    f"{e.get('firstName','')} {e.get('lastName','')}".strip(),
                        "uid":     e.get("uid"),
                        "type":    e.get("sdnType"),
                        "program": e.get("programList",""),
                        "source":  "US OFAC SDN",
                    })
                result["lists_checked"].append("US OFAC SDN List")
            except Exception:
                pass

        result["risk_level"]    = "CRITICAL" if result["sanctioned"] else "CLEAR"
        result["opensanctions"] = f"https://www.opensanctions.org/search/?q={name}"
        return result

    # ──────────────────────────────────────────────────────────
    # ICIJ OFFSHORE LEAKS (Panama Papers, Pandora Papers, etc.)
    # ──────────────────────────────────────────────────────────
    def icij_offshore_search(self, name: str) -> Dict:
        """Search ICIJ Offshore Leaks database (Panama Papers, Pandora Papers, etc.)."""
        resp = safe_request(
            "https://offshoreleaks.icij.org/api/search",
            params={"q": name, "c": "", "j": "", "cat": "0"}
        )
        result = {"query": name, "results": [], "total": 0,
                  "databases": ["Panama Papers", "Pandora Papers",
                                "Paradise Papers", "Bahamas Leaks"]}

        if resp and resp.status_code == 200:
            try:
                data  = resp.json()
                nodes = data.get("nodes", [])
                result["total"] = len(nodes)
                for n in nodes[:20]:
                    result["results"].append({
                        "name":      n.get("name"),
                        "type":      n.get("labels", [None])[0],
                        "countries": n.get("countries", []),
                        "datasets":  n.get("datasets", []),
                        "node_id":   n.get("node_id"),
                        "link_to":   f"https://offshoreleaks.icij.org/nodes/{n.get('node_id')}",
                    })
            except Exception as e:
                result["error"] = str(e)

        result["search_url"] = f"https://offshoreleaks.icij.org/search?q={name}"
        return result

    # ──────────────────────────────────────────────────────────
    # SEC EDGAR — INSIDER TRADING (Form 4)
    # ──────────────────────────────────────────────────────────
    def sec_insider_trading(self, name: str) -> Dict:
        """Search SEC EDGAR Form 4 filings for insider trading activity."""
        resp = safe_request(
            "https://efts.sec.gov/LATEST/search-index",
            params={
                "q":        f'"{name}"',
                "forms":    "4",
                "dateRange":"custom",
                "startdt":  "2020-01-01",
                "enddt":    "2025-12-31",
            }
        )
        trades = []
        if resp and resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            for h in hits[:15]:
                src = h.get("_source", {})
                trades.append({
                    "filer":       src.get("display_names", [{}])[0].get("name") if src.get("display_names") else name,
                    "company":     src.get("entity_name"),
                    "file_date":   src.get("file_date"),
                    "form":        src.get("form_type"),
                    "description": src.get("file_description","")[:100],
                    "edgar_url":   f"https://www.sec.gov{src.get('file_date','')}",
                })

        return {
            "query":         name,
            "form4_filings": trades,
            "count":         len(trades),
            "edgar_search":  f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={name}&type=4&dateb=&owner=include&count=40",
        }

    def sec_company_filings(self, company: str, form_type: str = "10-K") -> Dict:
        """Get SEC EDGAR filings for a company."""
        resp = safe_request(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": f'"{company}"', "forms": form_type,
                    "dateRange": "custom", "startdt": "2020-01-01"}
        )
        filings = []
        if resp and resp.status_code == 200:
            for h in resp.json().get("hits", {}).get("hits", [])[:10]:
                src = h.get("_source",{})
                filings.append({
                    "company":    src.get("entity_name"),
                    "form":       src.get("form_type"),
                    "filed":      src.get("file_date"),
                    "period":     src.get("period_of_report"),
                    "cik":        src.get("entity_id"),
                    "description":src.get("file_description","")[:100],
                })

        return {"company": company, "form_type": form_type,
                "filings": filings, "count": len(filings)}

    # ──────────────────────────────────────────────────────────
    # BENEFICIAL OWNERSHIP
    # ──────────────────────────────────────────────────────────
    def beneficial_ownership(self, company: str, jurisdiction: str = None) -> Dict:
        """
        Search OpenCorporates for beneficial ownership and company officers.
        """
        params = {"q": company, "format": "json", "per_page": 5}
        if jurisdiction:
            params["jurisdiction_code"] = jurisdiction

        resp = safe_request(
            "https://api.opencorporates.com/v0.4/companies/search",
            params=params
        )
        companies = []
        if resp and resp.status_code == 200:
            for item in resp.json().get("results",{}).get("companies",[]):
                c = item.get("company",{})
                companies.append({
                    "name":         c.get("name"),
                    "number":       c.get("company_number"),
                    "jurisdiction": c.get("jurisdiction_code"),
                    "status":       c.get("current_status"),
                    "incorporated": c.get("incorporation_date"),
                    "address":      c.get("registered_address",{}).get("in_full"),
                    "oc_url":       c.get("opencorporates_url"),
                })

        return {
            "query":     company,
            "companies": companies,
            "count":     len(companies),
            "note":      "Officer/UBO data available via OpenCorporates API key",
        }

    # ──────────────────────────────────────────────────────────
    # FULL FINANCIAL PROFILE
    # ──────────────────────────────────────────────────────────
    def full_financial_profile(self, target: str) -> Dict:
        return {
            "target":            target,
            "ofac_sanctions":    self.ofac_check(target),
            "offshore_leaks":    self.icij_offshore_search(target),
            "insider_trading":   self.sec_insider_trading(target),
            "beneficial_ownership": self.beneficial_ownership(target),
        }
