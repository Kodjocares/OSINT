#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              OSINT INTELLIGENCE TOOL  v2.0                   ║
║         Open Source Intelligence Framework — Python          ║
║      For authorized security research purposes only          ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import os
import json
import logging
import argparse
import getpass
from datetime import datetime
from typing import Dict, List

try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.syntax  import Syntax
    from rich.text    import Text
    from rich         import box
    RICH = True
except ImportError:
    RICH = False
    print("[!] Install 'rich' for best experience: pip install rich")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Original modules ──────────────────────────────────────────
from config import (OUTPUT_DIR, LOG_LEVEL, GITHUB_TOKEN, OTX_API_KEY,
                    ABUSEIPDB_KEY, SECURITYTRAILS_KEY, ETHERSCAN_KEY,
                    IPQUALITYSCORE_KEY, TINEYE_KEY, IPINFO_TOKEN)
from modules.username_lookup    import UsernameLookup
from modules.domain_intel       import DomainIntel
from modules.phone_lookup       import PhoneLookup
from modules.breach_check       import BreachCheck
from modules.social_media       import SocialMediaScraper
from modules.metadata_extractor import MetadataExtractor
from modules.google_dorking     import GoogleDorking
from modules.geolocation        import GeoLocation
from modules.monitoring         import Monitor
from reporting.report_generator import ReportGenerator
from utils.anonymity            import AnonymityManager
from utils.helpers              import save_json

# ── New modules ───────────────────────────────────────────────
from modules.web_archive        import WebArchive
from modules.github_recon       import GitHubRecon
from modules.paste_monitor      import PasteMonitor
from modules.company_intel      import CompanyIntel
from modules.threat_intel       import ThreatIntel
from modules.email_header       import EmailHeaderAnalyzer
from modules.reverse_image      import ReverseImageSearch
from modules.crypto_tracer      import CryptoTracer
from modules.dns_history        import DNSHistory
from modules.network_intel      import NetworkIntel
from modules.cloud_discovery    import CloudDiscovery
from modules.web_crawler        import WebCrawler
from modules.ip_classifier      import IPClassifier
from modules.graph_viz          import GraphViz
# ── v3.0 New Categories ───────────────────────
from modules.malware_analysis   import MalwareAnalysis
from modules.darkweb_intel      import DarkWebIntel
from modules.cert_transparency  import CertTransparency
from modules.wireless_intel     import WirelessIntel
from modules.physical_intel     import PhysicalIntel
from modules.financial_intel    import FinancialIntel
from modules.career_intel       import CareerIntel
from modules.workflow           import Workflow
from config import (HYBRID_ANALYSIS_KEY, WIGLE_KEY, CENSYS_API_ID,
                    CENSYS_API_SECRET, MARINETRAFFIC_KEY, USE_TOR, TOR_PROXY)

# ── Setup ─────────────────────────────────────────────────────
os.makedirs(OUTPUT_DIR, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(OUTPUT_DIR, "osint_tool.log")),
        logging.StreamHandler(),
    ],
)
logger  = logging.getLogger("osint")
console = Console() if RICH else None

BANNER = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝  v2.0
"""

MENU = """
╔══════════════════════════════════════════════════════════════╗
║         OSINT INTELLIGENCE TOOL v3.0 — 35 Modules           ║
╠══════════════════════════════════════════════════════════════╣
║  CORE MODULES                                                ║
║  [1]  Username / Email          [2]  Domain & IP             ║
║  [3]  Phone Tracking            [4]  Breach Check            ║
║  [5]  Password Exposure         [6]  Social Media            ║
║  [7]  Metadata Extraction       [8]  Google Dorks            ║
║  [9]  Geolocation               [10] Monitoring              ║
╠══════════════════════════════════════════════════════════════╣
║  NETWORK & WEB                                               ║
║  [11] Web Archive / Wayback     [12] GitHub Recon            ║
║  [13] Paste Monitor             [14] Company Intel           ║
║  [15] Threat Intel / IOC        [16] Email Header            ║
║  [17] Reverse Image Search      [18] Crypto Tracer           ║
║  [19] DNS History               [20] ASN / Network           ║
║  [21] Cloud Asset Discovery     [22] Web Crawler             ║
║  [23] IP Classifier             [24] Entity Graph            ║
╠══════════════════════════════════════════════════════════════╣
║  NEW CATEGORIES                                              ║
║  [27] Malware Analysis          [28] Dark Web Intel          ║
║  [29] Cert Transparency         [30] WiFi / Bluetooth        ║
║  [31] Vehicle & Physical        [32] Financial Intel         ║
║  [33] Career Intelligence       [34] Playbook Runner         ║
╠══════════════════════════════════════════════════════════════╣
║  [25] Full Investigation        [26] Anonymity               ║
║  [35] List All Playbooks        [0]  Exit                    ║
╚══════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────
# OSINT ENGINE
# ─────────────────────────────────────────────────────────────
class OSINTTool:
    def __init__(self, hibp_api_key: str = ""):
        # Original
        self.username_lookup  = UsernameLookup()
        self.domain_intel     = DomainIntel()
        self.phone_lookup     = PhoneLookup()
        self.breach_check     = BreachCheck(hibp_api_key=hibp_api_key)
        self.social_media     = SocialMediaScraper()
        self.metadata         = MetadataExtractor()
        self.dorking          = GoogleDorking()
        self.geolocation      = GeoLocation()
        self.monitor          = Monitor()
        self.reporter         = ReportGenerator(OUTPUT_DIR)
        self.anonymity        = AnonymityManager()
        # New
        self.web_archive      = WebArchive()
        self.github_recon     = GitHubRecon(github_token=GITHUB_TOKEN)
        self.paste_monitor    = PasteMonitor()
        self.company_intel    = CompanyIntel()
        self.threat_intel     = ThreatIntel(otx_key=OTX_API_KEY, abuseipdb_key=ABUSEIPDB_KEY)
        self.email_header     = EmailHeaderAnalyzer()
        self.reverse_image    = ReverseImageSearch()
        self.crypto_tracer    = CryptoTracer(etherscan_key=ETHERSCAN_KEY)
        self.dns_history      = DNSHistory(securitytrails_key=SECURITYTRAILS_KEY)
        self.network_intel    = NetworkIntel(ipinfo_token=IPINFO_TOKEN)
        self.cloud_discovery  = CloudDiscovery()
        self.web_crawler      = WebCrawler()
        self.ip_classifier    = IPClassifier(ipqs_key=IPQUALITYSCORE_KEY,
                                              abuseipdb_key=ABUSEIPDB_KEY)
        self.graph_viz        = GraphViz()
        # ── v3.0 New Categories ───────────────────
        self.malware          = MalwareAnalysis(hybrid_key=HYBRID_ANALYSIS_KEY)
        self.darkweb          = DarkWebIntel(use_tor=USE_TOR, tor_proxy=TOR_PROXY)
        self.cert_trans       = CertTransparency(censys_id=CENSYS_API_ID,
                                                  censys_secret=CENSYS_API_SECRET)
        self.wireless         = WirelessIntel(wigle_key=WIGLE_KEY)
        self.physical         = PhysicalIntel(marinetraffic_key=MARINETRAFFIC_KEY)
        self.financial        = FinancialIntel()
        self.career           = CareerIntel()
        # Workflow gets all modules injected
        self.workflow         = Workflow(modules_dict={
            "breach_check":    self.breach_check,
            "username_lookup": self.username_lookup,
            "paste_monitor":   self.paste_monitor,
            "threat_intel":    self.threat_intel,
            "ip_classifier":   self.ip_classifier,
            "domain_intel":    self.domain_intel,
            "cert_transparency": self.cert_trans,
            "dns_history":     self.dns_history,
            "cloud_discovery": self.cloud_discovery,
            "web_archive":     self.web_archive,
            "company_intel":   self.company_intel,
            "financial_intel": self.financial,
            "career_intel":    self.career,
            "social_media":    self.social_media,
            "github_recon":    self.github_recon,
            "geolocation":     self.geolocation,
            "network_intel":   self.network_intel,
            "darkweb_intel":   self.darkweb,
        })

    # ── 1 ─────────────────────────────────────────────────────
    def username_email_lookup(self, target: str) -> Dict:
        if "@" in target:
            return {"type":"email","target":target,
                    "data": self.username_lookup.investigate_email(target)}
        return {"type":"username","target":target,
                "data": self.username_lookup.search_username(target)}

    # ── 2 ─────────────────────────────────────────────────────
    def domain_ip_intelligence(self, target: str) -> Dict:
        import socket
        is_ip = False
        try: socket.inet_aton(target); is_ip = True
        except Exception: pass
        if is_ip:
            return {"type":"ip","target":target,"data":{
                "ip_lookup":   self.domain_intel.ip_lookup(target),
                "geolocation": self.geolocation.ip_geolocation(target),
            }}
        return {"type":"domain","target":target,"data":{
            "whois":        self.domain_intel.whois_lookup(target),
            "dns":          self.domain_intel.dns_lookup(target),
            "subdomains":   self.domain_intel.enumerate_subdomains(target),
            "ssl":          self.domain_intel.ssl_certificate_info(target),
            "technologies": self.domain_intel.fingerprint_technologies(target),
            "geolocation":  self.geolocation.domain_geolocation(target),
        }}

    # ── 3 ─────────────────────────────────────────────────────
    def phone_tracking(self, phone: str) -> Dict:
        return {"type":"phone","target":phone,
                "data": self.phone_lookup.lookup(phone)}

    # ── 4 ─────────────────────────────────────────────────────
    def breach_data_check(self, email: str) -> Dict:
        return {"type":"breach","target":email,
                "data": self.breach_check.check_email(email)}

    # ── 5 ─────────────────────────────────────────────────────
    def password_exposure_check(self, password: str) -> Dict:
        return {"type":"password_check",
                "data": self.breach_check.check_password(password)}

    # ── 6 ─────────────────────────────────────────────────────
    def social_media_scan(self, username: str) -> Dict:
        return {"type":"social","target":username,
                "data": self.social_media.full_social_scan(username)}

    # ── 7 ─────────────────────────────────────────────────────
    def metadata_extraction(self, source: str) -> Dict:
        return {"type":"metadata","source":source,
                "data": self.metadata.extract(source)}

    # ── 8 ─────────────────────────────────────────────────────
    def google_dorking(self, target: str, execute: bool = False,
                       categories: List[str] = None) -> Dict:
        if execute:
            return {"type":"dork_campaign","target":target,
                    "data": self.dorking.run_dork_campaign(target,categories=categories)}
        return {"type":"dorks_generated","target":target,
                "data": self.dorking.generate_dorks(target,categories=categories)}

    # ── 9 ─────────────────────────────────────────────────────
    def geolocation_lookup(self, target: str) -> Dict:
        import re, socket
        if re.match(r"^[-+]?\d+\.?\d*,\s*[-+]?\d+\.?\d*$", target):
            lat, lon = map(float, target.split(","))
            return {"type":"reverse_geocode","target":target,
                    "data": self.geolocation.reverse_geocode(lat, lon)}
        try:
            socket.inet_aton(target)
            return {"type":"ip_geo","target":target,
                    "data": self.geolocation.ip_geolocation(target)}
        except Exception:
            return {"type":"domain_geo","target":target,
                    "data": self.geolocation.domain_geolocation(target)}

    # ── 10 ────────────────────────────────────────────────────
    def setup_monitoring(self, target_id: str, target_type: str,
                         target_value: str, description: str = "") -> Dict:
        return self.monitor.register_target(target_id, target_type,
                                            target_value, description)

    # ── 11 — Web Archive ──────────────────────────────────────
    def web_archive_lookup(self, url: str, snapshot: bool = False,
                           timestamp: str = None) -> Dict:
        if snapshot:
            return {"type":"archive_snapshot","url":url,
                    "data": self.web_archive.extract_snapshot_content(url, timestamp)}
        return {"type":"archive_timeline","url":url,
                "data": self.web_archive.domain_timeline(url)}

    # ── 12 — GitHub Recon ─────────────────────────────────────
    def github_recon_scan(self, target: str, scan_secrets: bool = False,
                          repo: str = None) -> Dict:
        if repo:
            return {"type":"github_secrets","repo":repo,
                    "data": self.github_recon.scan_repo_for_secrets(repo)}
        if "." in target:
            return {"type":"github_domain_exposure","target":target,
                    "data": self.github_recon.search_domain_exposure(target)}
        result = self.github_recon.user_recon(target)
        if scan_secrets and result.get("repos"):
            all_findings = []
            for r in result["repos"][:5]:
                fn = r.get("full_name","")
                if fn:
                    sr = self.github_recon.scan_repo_for_secrets(fn, max_files=20)
                    all_findings.extend(sr.get("findings",[]))
            result["secret_findings"] = all_findings
        return {"type":"github_recon","target":target,"data":result}

    # ── 13 — Paste Monitor ────────────────────────────────────
    def paste_monitor_search(self, query: str, analyze_url: str = None) -> Dict:
        if analyze_url:
            return {"type":"paste_analysis","url":analyze_url,
                    "data": self.paste_monitor.analyze_paste(analyze_url)}
        return {"type":"paste_search","query":query,
                "data": self.paste_monitor.search_all(query)}

    # ── 14 — Company Intel ────────────────────────────────────
    def company_intelligence(self, company_name: str) -> Dict:
        return {"type":"company_intel","company":company_name,
                "data": self.company_intel.full_company_profile(company_name)}

    # ── 15 — Threat Intel ─────────────────────────────────────
    def threat_intelligence(self, ioc: str, ioc_type: str = "auto") -> Dict:
        import re, socket
        if ioc_type == "auto":
            if re.match(r"\b[a-fA-F0-9]{32,64}\b", ioc):
                ioc_type = "hash"
            elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ioc):
                ioc_type = "ip"
            elif ioc.startswith("http"):
                ioc_type = "url"
            else:
                ioc_type = "domain"

        if ioc_type == "ip":
            return {"type":"threat_ip","ioc":ioc,
                    "data": self.threat_intel.ip_reputation(ioc)}
        elif ioc_type == "domain":
            return {"type":"threat_domain","ioc":ioc,
                    "data": self.threat_intel.domain_reputation(ioc)}
        elif ioc_type == "hash":
            return {"type":"threat_hash","ioc":ioc,
                    "data": self.threat_intel.file_hash_lookup(ioc)}
        elif ioc_type == "url":
            return {"type":"threat_url","ioc":ioc,
                    "data": self.threat_intel.url_analysis(ioc)}
        return {"error": f"Unknown IOC type: {ioc_type}"}

    # ── 16 — Email Header ─────────────────────────────────────
    def analyze_email_header(self, raw_headers: str = None,
                              filepath: str = None) -> Dict:
        if filepath and os.path.exists(filepath):
            with open(filepath, "r", errors="replace") as f:
                raw_headers = f.read()
        if not raw_headers:
            return {"error": "No header data provided"}
        return {"type":"email_header",
                "data": self.email_header.analyze(raw_headers)}

    # ── 17 — Reverse Image ────────────────────────────────────
    def reverse_image_search(self, image_source: str) -> Dict:
        analysis = self.reverse_image.analyze_image(image_source)
        if image_source.startswith("http"):
            analysis["search_engines"] = self.reverse_image.generate_search_urls(image_source)["engines"]
        return {"type":"reverse_image","source":image_source,"data":analysis}

    # ── 18 — Crypto ───────────────────────────────────────────
    def crypto_trace(self, address: str) -> Dict:
        return {"type":"crypto","address":address,
                "data": self.crypto_tracer.lookup(address)}

    # ── 19 — DNS History ──────────────────────────────────────
    def dns_history_lookup(self, domain: str) -> Dict:
        return {"type":"dns_history","domain":domain,
                "data": self.dns_history.full_history(domain)}

    # ── 20 — Network / ASN ────────────────────────────────────
    def network_asn_lookup(self, target: str) -> Dict:
        import re
        if re.match(r"^[Aa][Ss]\d+$|^\d+$", target):
            return {"type":"asn","target":target,
                    "data": self.network_intel.asn_lookup(target)}
        elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target):
            return {"type":"ip_to_asn","target":target,"data":{
                "asn_info": self.network_intel.ip_to_asn(target),
                "rdap":     self.network_intel.rdap_lookup(target),
                "ports":    self.network_intel.quick_port_check(target),
            }}
        return {"type":"org_ranges","target":target,
                "data": self.network_intel.org_ip_ranges(target)}

    # ── 21 — Cloud Discovery ──────────────────────────────────
    def cloud_asset_scan(self, target: str) -> Dict:
        return {"type":"cloud_assets","target":target,
                "data": self.cloud_discovery.full_cloud_scan(target)}

    # ── 22 — Web Crawler ──────────────────────────────────────
    def crawl_website(self, url: str, max_pages: int = 30,
                      quick: bool = False) -> Dict:
        if quick:
            return {"type":"page_scrape","url":url,
                    "data": self.web_crawler.scrape_page(url)}
        crawler = WebCrawler(max_pages=max_pages)
        return {"type":"web_crawl","url":url,
                "data": crawler.crawl(url)}

    # ── 23 — IP Classifier ────────────────────────────────────
    def classify_ip(self, ip: str) -> Dict:
        return {"type":"ip_classification","ip":ip,
                "data": self.ip_classifier.classify(ip)}

    # ── 24 — Graph Viz ────────────────────────────────────────
    def build_graph(self, target: str, osint_data: Dict,
                    output_formats: List[str] = None) -> Dict:
        gv = GraphViz()
        gv.build_from_osint(target, osint_data)
        outputs = {}
        fmt = output_formats or ["html", "json"]
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c for c in target if c.isalnum() or c in "-_.")
        if "html" in fmt:
            outputs["html"] = gv.export_html(
                os.path.join(OUTPUT_DIR, f"graph_{safe}_{ts}.html"),
                title=f"OSINT Graph — {target}"
            )
        if "graphml" in fmt:
            outputs["graphml"] = gv.export_graphml(
                os.path.join(OUTPUT_DIR, f"graph_{safe}_{ts}.graphml")
            )
        if "json" in fmt:
            outputs["json"] = gv.export_json(
                os.path.join(OUTPUT_DIR, f"graph_{safe}_{ts}.json")
            )
        return {"type":"graph","target":target,
                "stats": gv.get_stats(), "outputs": outputs}

    # ── 25 — Full Investigation ───────────────────────────────
    def full_investigation(self, target: str,
                           output_formats: List[str] = None) -> Dict:
        import socket
        _print(f"[bold cyan]Starting Full Investigation: {target}[/bold cyan]")

        results = {
            "target":    target,
            "timestamp": datetime.now().isoformat(),
            "anonymity": self.anonymity.status_report(),
        }

        is_email  = "@" in target
        is_ip     = False
        try: socket.inet_aton(target); is_ip = True
        except Exception: pass
        is_domain = not is_email and not is_ip and "." in target

        steps: List = []
        if is_email:
            steps = [
                ("email_lookup",   lambda: self.username_email_lookup(target)),
                ("breach_check",   lambda: self.breach_data_check(target)),
                ("paste_search",   lambda: self.paste_monitor_search(target)),
                ("username_check", lambda: self.username_lookup.search_username(
                    target.split("@")[0])),
            ]
        elif is_ip:
            steps = [
                ("ip_intel",       lambda: self.domain_ip_intelligence(target)),
                ("threat_intel",   lambda: self.threat_intelligence(target,"ip")),
                ("ip_classifier",  lambda: self.classify_ip(target)),
                ("geolocation",    lambda: self.geolocation_lookup(target)),
                ("network_intel",  lambda: self.network_asn_lookup(target)),
            ]
        elif is_domain:
            steps = [
                ("domain_intel",   lambda: self.domain_ip_intelligence(target)),
                ("dns_history",    lambda: self.dns_history_lookup(target)),
                ("cloud_assets",   lambda: self.cloud_asset_scan(target)),
                ("threat_intel",   lambda: self.threat_intelligence(target,"domain")),
                ("web_archive",    lambda: self.web_archive_lookup(target)),
                ("google_dorks",   lambda: self.google_dorking(target)),
            ]
        else:
            steps = [
                ("username_lookup", lambda: self.username_email_lookup(target)),
                ("social_media",    lambda: self.social_media_scan(target)),
                ("github_recon",    lambda: self.github_recon_scan(target)),
                ("paste_search",    lambda: self.paste_monitor_search(target)),
            ]

        for step_name, step_fn in steps:
            _print(f"  [dim]→[/dim] [cyan]{step_name}[/cyan]")
            try:
                results[step_name] = step_fn()
            except Exception as e:
                results[step_name] = {"error": str(e)}
                logger.error(f"[FULL SCAN] {step_name} failed: {e}")

        # Generate reports
        fmts  = output_formats or ["html","json"]
        files = self.reporter.full_report(results, target, formats=fmts)
        results["report_files"] = files

        # Build graph
        try:
            graph_result = self.build_graph(target, results, output_formats=["html"])
            results["graph"] = graph_result
            if graph_result.get("outputs",{}).get("html"):
                files["graph"] = graph_result["outputs"]["html"]
        except Exception as e:
            logger.warning(f"[GRAPH] Failed: {e}")

        return results

    # ── 27 — Malware Analysis ─────────────────────────────────
    def malware_analysis(self, target: str, mode: str = "full") -> Dict:
        if mode == "strings":
            return {"type":"malware_strings","target":target,
                    "data": self.malware.extract_strings(target)}
        elif mode == "pe":
            return {"type":"malware_pe","target":target,
                    "data": self.malware.analyze_pe(target)}
        elif mode == "yara":
            return {"type":"malware_yara","target":target,
                    "data": self.malware.yara_quick_scan(target)}
        elif mode == "hash":
            return {"type":"malware_hash","target":target,
                    "data": self.malware.hash_file(target)}
        return {"type":"malware_full","target":target,
                "data": self.malware.full_analysis(target)}

    # ── 28 — Dark Web Intel ───────────────────────────────────
    def darkweb_search(self, target: str, mode: str = "full") -> Dict:
        if mode == "ahmia":
            return {"type":"darkweb_ahmia","target":target,
                    "data": self.darkweb.ahmia_search(target)}
        elif mode == "ransomware":
            return {"type":"darkweb_ransomware","target":target,
                    "data": self.darkweb.ransomware_leak_search(target)}
        elif mode == "paste":
            return {"type":"darkweb_paste","target":target,
                    "data": self.darkweb.dark_paste_search(target)}
        return {"type":"darkweb_full","target":target,
                "data": self.darkweb.full_profile(target)}

    # ── 29 — Certificate Transparency ────────────────────────
    def cert_transparency_scan(self, target: str, mode: str = "full") -> Dict:
        if mode == "typosquats":
            return {"type":"cert_typosquats","target":target,
                    "data": self.cert_trans.find_suspicious_certs(target)}
        elif mode == "org":
            return {"type":"cert_org","target":target,
                    "data": self.cert_trans.org_cert_search(target)}
        return {"type":"cert_full","target":target,
                "data": self.cert_trans.full_report(target)}

    # ── 30 — Wireless Intel ───────────────────────────────────
    def wireless_lookup(self, target: str) -> Dict:
        return {"type":"wireless","target":target,
                "data": self.wireless.full_wireless_profile(target)}

    # ── 31 — Physical / Vehicle ──────────────────────────────
    def physical_lookup(self, target: str, mode: str = "auto") -> Dict:
        import re
        if mode == "vin" or re.match(r"^[A-HJ-NPR-Z0-9]{17}$", target.upper()):
            return {"type":"vin","target":target,
                    "data": self.physical.decode_vin(target)}
        elif mode == "aircraft":
            return {"type":"aircraft","target":target,"data":{
                "faa":    self.physical.faa_aircraft_lookup(target),
                "opensky":self.physical.opensky_aircraft_track(target),
            }}
        elif mode == "vessel":
            return {"type":"vessel","target":target,
                    "data": self.physical.vessel_lookup(target)}
        # Default: try VIN
        return {"type":"vin","target":target,
                "data": self.physical.decode_vin(target)}

    # ── 32 — Financial Intel ──────────────────────────────────
    def financial_lookup(self, target: str, mode: str = "full") -> Dict:
        if mode == "ofac":
            return {"type":"ofac","target":target,
                    "data": self.financial.ofac_check(target)}
        elif mode == "offshore":
            return {"type":"offshore_leaks","target":target,
                    "data": self.financial.icij_offshore_search(target)}
        elif mode == "insider":
            return {"type":"insider_trading","target":target,
                    "data": self.financial.sec_insider_trading(target)}
        elif mode == "ownership":
            return {"type":"beneficial_ownership","target":target,
                    "data": self.financial.beneficial_ownership(target)}
        return {"type":"financial_full","target":target,
                "data": self.financial.full_financial_profile(target)}

    # ── 33 — Career Intel ─────────────────────────────────────
    def career_lookup(self, target: str, mode: str = "company") -> Dict:
        if mode == "jobs":
            return {"type":"job_postings","target":target,
                    "data": self.career.scrape_job_postings(target)}
        elif mode == "h1b":
            return {"type":"h1b","target":target,
                    "data": self.career.h1b_search(target)}
        elif mode == "patents":
            return {"type":"patents","target":target,
                    "data": self.career.patent_search(target)}
        is_company = mode != "person"
        return {"type":"career_full","target":target,
                "data": self.career.full_career_profile(target, is_company=is_company)}

    # ── 34 — Workflow / Playbooks ─────────────────────────────
    def run_playbook(self, target: str, playbook_id: str = "email_full",
                     webhook_url: str = "") -> Dict:
        result = self.workflow.run_playbook(playbook_id, target)
        if webhook_url:
            self.workflow.send_webhook(webhook_url, result)
        return result

    def list_playbooks(self) -> Dict:
        return self.workflow.list_playbooks()

    # ── 26 — Anonymity ────────────────────────────────────────
    def check_anonymity(self) -> Dict:
        return self.anonymity.status_report()


# ─────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────
def _print(msg: str):
    if RICH:
        console.print(msg)
    else:
        # strip rich markup for plain output
        import re
        print(re.sub(r"\[.*?\]","",msg))

def display_result(data: Dict, title: str = "Result"):
    if RICH:
        console.print(Panel(
            Syntax(json.dumps(data, indent=2, default=str), "json",
                   theme="monokai", line_numbers=False),
            title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan"
        ))
    else:
        print(json.dumps(data, indent=2, default=str))

def print_banner():
    if RICH:
        console.print(Text(BANNER, style="bold cyan"))
        console.print("[dim]For authorized OSINT research only — v2.0 | 27 modules[/dim]\n")
    else:
        print(BANNER)

def _save(result: Dict, label: str):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUTPUT_DIR, f"{label}_{ts}.json")
    save_json(result, path)
    _print(f"[dim]Saved: {path}[/dim]")
    return path


# ─────────────────────────────────────────────────────────────
# INTERACTIVE MODE
# ─────────────────────────────────────────────────────────────
def interactive_mode(tool: OSINTTool):
    print_banner()
    while True:
        if RICH:
            console.print(Panel(MENU, border_style="dim", padding=(0,1)))
        else:
            print(MENU)

        choice = input("  Select option: ").strip()

        if choice == "0":
            _print("[bold red]Exiting.[/bold red]"); break

        elif choice == "1":
            t = input("  Username or email: ").strip()
            if t:
                r = tool.username_email_lookup(t)
                display_result(r, f"Lookup: {t}"); _save(r, "lookup")

        elif choice == "2":
            t = input("  Domain or IP: ").strip()
            if t:
                r = tool.domain_ip_intelligence(t)
                display_result(r, f"Intel: {t}"); _save(r, "intel")

        elif choice == "3":
            t = input("  Phone (E.164, e.g. +14155552671): ").strip()
            if t:
                r = tool.phone_tracking(t)
                display_result(r, f"Phone: {t}"); _save(r, "phone")

        elif choice == "4":
            t = input("  Email: ").strip()
            if t:
                r = tool.breach_data_check(t)
                display_result(r, f"Breach: {t}"); _save(r, "breach")
                if r.get("data",{}).get("breach_count",0) > 0:
                    _print(f"[bold red]⚠  Found in {r['data']['breach_count']} breach(es)![/bold red]")

        elif choice == "5":
            _print("[dim]k-anonymity: only SHA-1 prefix sent. Password never transmitted.[/dim]")
            pw = getpass.getpass("  Password (hidden): ")
            if pw:
                r = tool.password_exposure_check(pw)
                display_result(r, "Password Check")

        elif choice == "6":
            t = input("  Username: ").strip()
            if t:
                r = tool.social_media_scan(t)
                display_result(r, f"Social: {t}"); _save(r, "social")

        elif choice == "7":
            t = input("  File path or URL: ").strip()
            if t:
                r = tool.metadata_extraction(t)
                display_result(r, "Metadata"); _save(r, "metadata")

        elif choice == "8":
            t = input("  Target domain: ").strip()
            ex = input("  Execute searches? (y/N): ").lower() == "y"
            if t:
                r = tool.google_dorking(t, execute=ex)
                display_result(r, f"Dorks: {t}"); _save(r, "dorks")

        elif choice == "9":
            t = input("  IP, domain, or coords (lat,lon): ").strip()
            if t:
                r = tool.geolocation_lookup(t)
                display_result(r, f"Geo: {t}"); _save(r, "geo")

        elif choice == "10":
            tid  = input("  Monitor ID: ").strip()
            ttyp = input("  Type (domain/ip/email/username): ").strip()
            tval = input("  Value: ").strip()
            desc = input("  Description (optional): ").strip()
            if tid and ttyp and tval:
                r = tool.setup_monitoring(tid, ttyp, tval, desc)
                display_result(r, "Monitor Registered")

        elif choice == "11":
            t = input("  URL or domain for archive lookup: ").strip()
            snap = input("  Fetch latest snapshot content? (y/N): ").lower() == "y"
            ts_  = input("  Specific timestamp (yyyymmddHHMMSS, or blank): ").strip() or None
            if t:
                r = tool.web_archive_lookup(t, snapshot=snap, timestamp=ts_)
                display_result(r, f"Archive: {t}"); _save(r, "archive")

        elif choice == "12":
            t    = input("  GitHub username, domain, or full repo (org/repo): ").strip()
            scan = input("  Deep secret scan? (y/N): ").lower() == "y"
            if t:
                r = tool.github_recon_scan(t, scan_secrets=scan,
                                           repo=t if "/" in t else None)
                display_result(r, f"GitHub: {t}"); _save(r, "github")

        elif choice == "13":
            t    = input("  Search query (email/domain/username): ").strip()
            url_ = input("  Or paste URL to analyze (blank to search): ").strip() or None
            if t or url_:
                r = tool.paste_monitor_search(t, analyze_url=url_)
                display_result(r, "Paste Monitor"); _save(r, "paste")

        elif choice == "14":
            t = input("  Company name: ").strip()
            if t:
                r = tool.company_intelligence(t)
                display_result(r, f"Company: {t}"); _save(r, "company")

        elif choice == "15":
            t = input("  IOC (IP / domain / hash / URL): ").strip()
            if t:
                r = tool.threat_intelligence(t)
                display_result(r, f"Threat Intel: {t}"); _save(r, "threat")

        elif choice == "16":
            path = input("  Path to saved email header file (or press Enter to paste): ").strip()
            if path and os.path.exists(path):
                r = tool.analyze_email_header(filepath=path)
            else:
                _print("[dim]Paste raw email headers below, then type END on a new line:[/dim]")
                lines = []
                while True:
                    line = input()
                    if line.strip() == "END":
                        break
                    lines.append(line)
                r = tool.analyze_email_header(raw_headers="\n".join(lines))
            display_result(r, "Email Header Analysis"); _save(r, "email_header")

        elif choice == "17":
            t = input("  Image URL or local file path: ").strip()
            if t:
                r = tool.reverse_image_search(t)
                display_result(r, f"Image: {t}"); _save(r, "image")

        elif choice == "18":
            t = input("  Crypto address (BTC/ETH): ").strip()
            if t:
                r = tool.crypto_trace(t)
                display_result(r, f"Crypto: {t}"); _save(r, "crypto")

        elif choice == "19":
            t = input("  Domain name: ").strip()
            if t:
                r = tool.dns_history_lookup(t)
                display_result(r, f"DNS History: {t}"); _save(r, "dns_history")

        elif choice == "20":
            t = input("  IP / ASN (e.g. AS15169) / org name: ").strip()
            if t:
                r = tool.network_asn_lookup(t)
                display_result(r, f"Network: {t}"); _save(r, "network")

        elif choice == "21":
            t = input("  Domain or company name: ").strip()
            if t:
                r = tool.cloud_asset_scan(t)
                display_result(r, f"Cloud Assets: {t}"); _save(r, "cloud")

        elif choice == "22":
            t    = input("  URL to crawl: ").strip()
            mp   = int(input("  Max pages (default 30): ").strip() or "30")
            qk   = input("  Quick single-page scrape? (y/N): ").lower() == "y"
            if t:
                r = tool.crawl_website(t, max_pages=mp, quick=qk)
                display_result(r, f"Crawl: {t}"); _save(r, "crawl")

        elif choice == "23":
            t = input("  IP address to classify: ").strip()
            if t:
                r = tool.classify_ip(t)
                display_result(r, f"IP Classifier: {t}"); _save(r, "ip_class")

        elif choice == "24":
            t    = input("  Target (used as root node): ").strip()
            data_file = input("  Path to existing OSINT JSON (blank to build empty graph): ").strip()
            osint_data = {}
            if data_file and os.path.exists(data_file):
                with open(data_file) as f:
                    osint_data = json.load(f)
            if t:
                r = tool.build_graph(t, osint_data)
                display_result(r, f"Graph: {t}")
                if r.get("outputs",{}).get("html"):
                    _print(f"[green]Graph: {r['outputs']['html']}[/green]")

        elif choice == "25":
            t   = input("  Target (email/domain/IP/username): ").strip()
            fmt = input("  Report formats html,json (default both): ").strip()
            fmts = [f.strip() for f in fmt.split(",")] if fmt else ["html","json"]
            if t:
                r = tool.full_investigation(t, output_formats=fmts)
                _print("[bold green]✓ Full Investigation Complete[/bold green]")
                for k, v in r.get("report_files",{}).items():
                    _print(f"  [cyan]{k}:[/cyan] {v}")

        elif choice == "26":
            r = tool.check_anonymity()
            display_result(r, "Anonymity Status")


        elif choice == "27":
            t    = input("  File path or hash (MD5/SHA256): ").strip()
            mode = input("  Mode [full/strings/pe/yara/hash] (default full): ").strip() or "full"
            if t:
                r = tool.malware_analysis(t, mode=mode)
                display_result(r, f"Malware: {t}"); _save(r, "malware")

        elif choice == "28":
            t    = input("  Target (domain/company/name): ").strip()
            mode = input("  Mode [full/ahmia/ransomware/paste] (default full): ").strip() or "full"
            if t:
                r = tool.darkweb_search(t, mode=mode)
                display_result(r, f"Dark Web: {t}"); _save(r, "darkweb")

        elif choice == "29":
            t    = input("  Domain or organisation name: ").strip()
            mode = input("  Mode [full/typosquats/org] (default full): ").strip() or "full"
            if t:
                r = tool.cert_transparency_scan(t, mode=mode)
                display_result(r, f"Cert Transparency: {t}"); _save(r, "cert")

        elif choice == "30":
            t = input("  SSID name, BSSID (AA:BB:CC:DD:EE:FF), or MAC address: ").strip()
            if t:
                r = tool.wireless_lookup(t)
                display_result(r, f"Wireless: {t}"); _save(r, "wireless")

        elif choice == "31":
            t    = input("  VIN, N-number (aircraft), or MMSI (vessel): ").strip()
            mode = input("  Mode [auto/vin/aircraft/vessel] (default auto): ").strip() or "auto"
            if t:
                r = tool.physical_lookup(t, mode=mode)
                display_result(r, f"Physical: {t}"); _save(r, "physical")

        elif choice == "32":
            t    = input("  Person or company name: ").strip()
            mode = input("  Mode [full/ofac/offshore/insider/ownership] (default full): ").strip() or "full"
            if t:
                r = tool.financial_lookup(t, mode=mode)
                display_result(r, f"Financial: {t}"); _save(r, "financial")

        elif choice == "33":
            t    = input("  Company or person name: ").strip()
            mode = input("  Mode [company/person/jobs/h1b/patents] (default company): ").strip() or "company"
            if t:
                r = tool.career_lookup(t, mode=mode)
                display_result(r, f"Career: {t}"); _save(r, "career")

        elif choice == "34":
            t    = input("  Target (email/domain/IP/username): ").strip()
            pbs  = tool.list_playbooks()
            _print("[dim]Available playbooks:[/dim]")
            for pb in pbs.get("playbooks", []):
                _print(f"  [cyan]{pb['id']}[/cyan] — {pb['name']} ({pb['step_count']} steps)")
            pb_id = input("  Playbook ID (default: email_full): ").strip() or "email_full"
            wh    = input("  Webhook URL for alert (optional, press Enter to skip): ").strip()
            if t:
                _print(f"[dim]Running playbook '{pb_id}' on {t}...[/dim]")
                r = tool.run_playbook(t, playbook_id=pb_id, webhook_url=wh)
                display_result(r, f"Playbook: {pb_id} → {t}")
                _print(f"[green]✓ {r.get('completed',0)}/{r.get('total_steps',0)} steps completed[/green]")
                if r.get("output_file"):
                    _print(f"[dim]Saved: {r['output_file']}[/dim]")

        elif choice == "35":
            r = tool.list_playbooks()
            display_result(r, "Available Playbooks")

        else:
            _print("[red]Invalid option.[/red]")


# ─────────────────────────────────────────────────────────────
# CLI MODE
# ─────────────────────────────────────────────────────────────
def cli_mode():
    p = argparse.ArgumentParser(
        description="OSINT Intelligence Tool v3.0 — 35 modules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --username johndoe
  python main.py --email target@example.com
  python main.py --domain example.com
  python main.py --ip 8.8.8.8
  python main.py --phone "+14155552671"
  python main.py --breach user@example.com
  python main.py --password-check
  python main.py --social johndoe
  python main.py --metadata /path/to/image.jpg
  python main.py --dork example.com --dork-execute
  python main.py --geo 8.8.8.8
  python main.py --archive example.com
  python main.py --github johndoe --scan-secrets
  python main.py --github org/repo --scan-secrets
  python main.py --paste "user@example.com"
  python main.py --company "Acme Corp"
  python main.py --threat 8.8.8.8
  python main.py --threat d41d8cd98f00b204e9800998ecf8427e
  python main.py --email-header /path/to/headers.txt
  python main.py --image https://example.com/photo.jpg
  python main.py --crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf
  python main.py --dns-history example.com
  python main.py --asn AS15169
  python main.py --cloud example.com
  python main.py --crawl https://example.com --max-pages 50
  python main.py --classify-ip 8.8.8.8
  python main.py --graph target@example.com --graph-data results.json
  python main.py --full target@example.com --output html,json
  python main.py --malware /path/to/sample.exe
  python main.py --malware d41d8cd98f00b204e9800998ecf8427e
  python main.py --malware /path/to/file.exe --malware-mode strings
  python main.py --darkweb "Acme Corp"
  python main.py --darkweb "Acme Corp" --darkweb-mode ransomware
  python main.py --cert-trans example.com
  python main.py --cert-trans example.com --cert-mode typosquats
  python main.py --wireless "HomeNetwork"
  python main.py --wireless "AA:BB:CC:DD:EE:FF"
  python main.py --physical 1HGBH41JXMN109186
  python main.py --physical N172UP --physical-mode aircraft
  python main.py --financial "Acme Corp"
  python main.py --financial "John Smith" --financial-mode ofac
  python main.py --career "Google" --career-mode jobs
  python main.py --career "Jane Doe" --career-mode patents
  python main.py --playbook target@example.com --playbook-id email_full
  python main.py --playbook example.com --playbook-id domain_full --webhook https://hooks.slack.com/...
  python main.py --list-playbooks
  python main.py --interactive
        """
    )

    # Original flags
    p.add_argument("--username",       help="Username lookup")
    p.add_argument("--email",          help="Email investigation")
    p.add_argument("--domain",         help="Domain intelligence")
    p.add_argument("--ip",             help="IP intelligence")
    p.add_argument("--phone",          help="Phone number lookup")
    p.add_argument("--breach",         help="Email breach check")
    p.add_argument("--password-check", action="store_true")
    p.add_argument("--social",         help="Social media scan")
    p.add_argument("--metadata",       help="Metadata extraction")
    p.add_argument("--dork",           help="Google dorking target")
    p.add_argument("--dork-execute",   action="store_true")
    p.add_argument("--geo",            help="Geolocation")

    # New flags
    p.add_argument("--archive",        help="Wayback Machine lookup (URL or domain)")
    p.add_argument("--archive-snapshot", action="store_true", help="Fetch snapshot content")
    p.add_argument("--archive-ts",     help="Archive timestamp (yyyymmddHHMMSS)")
    p.add_argument("--github",         help="GitHub recon (username, domain, or org/repo)")
    p.add_argument("--scan-secrets",   action="store_true", help="Deep secret scan")
    p.add_argument("--paste",          help="Paste site search query")
    p.add_argument("--paste-url",      help="Analyze a specific paste URL")
    p.add_argument("--company",        help="Company intelligence")
    p.add_argument("--threat",         help="Threat intel / IOC lookup")
    p.add_argument("--ioc-type",       default="auto",
                   help="IOC type: ip|domain|hash|url (default: auto)")
    p.add_argument("--email-header",   help="Path to raw email header file")
    p.add_argument("--image",          help="Reverse image search (URL or file path)")
    p.add_argument("--crypto",         help="Cryptocurrency address lookup")
    p.add_argument("--dns-history",    help="DNS history for domain")
    p.add_argument("--asn",            help="ASN lookup (e.g. AS15169 or IP)")
    p.add_argument("--cloud",          help="Cloud asset discovery for domain/company")
    p.add_argument("--crawl",          help="Crawl a website")
    p.add_argument("--max-pages",      type=int, default=30)
    p.add_argument("--quick-scrape",   action="store_true")
    p.add_argument("--classify-ip",    help="Classify IP as VPN/Tor/Proxy/Datacenter")
    p.add_argument("--graph",          help="Build entity graph for target")
    p.add_argument("--graph-data",     help="Path to OSINT JSON for graph building")

    # Meta

    # ── v3.0 New Categories ───────────────────────────────────
    p.add_argument("--malware",        help="Malware analysis (file path or hash)")
    p.add_argument("--malware-mode",   default="full",
                   help="Analysis mode: full|strings|pe|yara|hash")
    p.add_argument("--darkweb",        help="Dark web search (domain/company/name)")
    p.add_argument("--darkweb-mode",   default="full",
                   help="Mode: full|ahmia|ransomware|paste")
    p.add_argument("--cert-trans",     help="Certificate transparency (domain or org)")
    p.add_argument("--cert-mode",      default="full",
                   help="Mode: full|typosquats|org")
    p.add_argument("--wireless",       help="WiFi/Bluetooth lookup (SSID or BSSID/MAC)")
    p.add_argument("--physical",       help="Vehicle/physical lookup (VIN/N-number/MMSI)")
    p.add_argument("--physical-mode",  default="auto",
                   help="Mode: auto|vin|aircraft|vessel")
    p.add_argument("--financial",      help="Financial intelligence (person/company)")
    p.add_argument("--financial-mode", default="full",
                   help="Mode: full|ofac|offshore|insider|ownership")
    p.add_argument("--career",         help="Career intelligence (company/person)")
    p.add_argument("--career-mode",    default="company",
                   help="Mode: company|person|jobs|h1b|patents")
    p.add_argument("--playbook",       help="Run investigation playbook on target")
    p.add_argument("--playbook-id",    default="email_full",
                   help="Playbook ID (email_full|domain_full|person_full|ip_full|company_full|threat_hunt)")
    p.add_argument("--list-playbooks", action="store_true",
                   help="List all available playbooks")
    p.add_argument("--webhook",        default="",
                   help="Webhook URL for playbook completion alert (Slack/Discord/Teams)")

    p.add_argument("--full",           help="Full investigation")
    p.add_argument("--output",         default="html,json")
    p.add_argument("--hibp-key",       default="")
    p.add_argument("--interactive",    action="store_true")
    p.add_argument("--anonymity",      action="store_true")

    args = p.parse_args()
    tool = OSINTTool(hibp_api_key=args.hibp_key)
    fmts = [f.strip() for f in args.output.split(",")]

    if args.interactive or len(sys.argv) == 1:
        interactive_mode(tool); return

    result = None

    if args.username:         result = tool.username_email_lookup(args.username)
    elif args.email:          result = tool.username_email_lookup(args.email)
    elif args.domain:         result = tool.domain_ip_intelligence(args.domain)
    elif args.ip:             result = tool.domain_ip_intelligence(args.ip)
    elif args.phone:          result = tool.phone_tracking(args.phone)
    elif args.breach:         result = tool.breach_data_check(args.breach)
    elif args.password_check:
        pw = getpass.getpass("Password (hidden): ")
        result = tool.password_exposure_check(pw)
    elif args.social:         result = tool.social_media_scan(args.social)
    elif args.metadata:       result = tool.metadata_extraction(args.metadata)
    elif args.dork:           result = tool.google_dorking(args.dork, execute=args.dork_execute)
    elif args.geo:            result = tool.geolocation_lookup(args.geo)
    elif args.archive:        result = tool.web_archive_lookup(
                                  args.archive, snapshot=args.archive_snapshot,
                                  timestamp=args.archive_ts)
    elif args.github:         result = tool.github_recon_scan(
                                  args.github, scan_secrets=args.scan_secrets,
                                  repo=args.github if "/" in args.github else None)
    elif args.paste:          result = tool.paste_monitor_search(args.paste,
                                  analyze_url=args.paste_url)
    elif args.company:        result = tool.company_intelligence(args.company)
    elif args.threat:         result = tool.threat_intelligence(args.threat, args.ioc_type)
    elif args.email_header:   result = tool.analyze_email_header(filepath=args.email_header)
    elif args.image:          result = tool.reverse_image_search(args.image)
    elif args.crypto:         result = tool.crypto_trace(args.crypto)
    elif args.dns_history:    result = tool.dns_history_lookup(args.dns_history)
    elif args.asn:            result = tool.network_asn_lookup(args.asn)
    elif args.cloud:          result = tool.cloud_asset_scan(args.cloud)
    elif args.crawl:          result = tool.crawl_website(args.crawl,
                                  max_pages=args.max_pages, quick=args.quick_scrape)
    elif args.classify_ip:    result = tool.classify_ip(args.classify_ip)
    elif args.graph:
        osint_data = {}
        if args.graph_data and os.path.exists(args.graph_data):
            with open(args.graph_data) as f:
                osint_data = json.load(f)
        result = tool.build_graph(args.graph, osint_data)

    elif args.malware:        result = tool.malware_analysis(args.malware,
                                  mode=getattr(args,"malware_mode","full"))
    elif args.darkweb:        result = tool.darkweb_search(args.darkweb,
                                  mode=getattr(args,"darkweb_mode","full"))
    elif args.cert_trans:     result = tool.cert_transparency_scan(args.cert_trans,
                                  mode=getattr(args,"cert_mode","full"))
    elif args.wireless:       result = tool.wireless_lookup(args.wireless)
    elif args.physical:       result = tool.physical_lookup(args.physical,
                                  mode=getattr(args,"physical_mode","auto"))
    elif args.financial:      result = tool.financial_lookup(args.financial,
                                  mode=getattr(args,"financial_mode","full"))
    elif args.career:         result = tool.career_lookup(args.career,
                                  mode=getattr(args,"career_mode","company"))
    elif args.playbook:       result = tool.run_playbook(
                                  args.playbook,
                                  playbook_id=getattr(args,"playbook_id","email_full"),
                                  webhook_url=getattr(args,"webhook",""))
    elif getattr(args,"list_playbooks",False):
                              result = tool.list_playbooks()
    elif args.full:           result = tool.full_investigation(args.full,
                                  output_formats=fmts)
    elif args.anonymity:      result = tool.check_anonymity()

    if result:
        display_result(result)
        _save(result, "result")


if __name__ == "__main__":
    cli_mode()
