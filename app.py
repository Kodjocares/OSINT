#!/usr/bin/env python3
"""
app.py — OSINT Tool Web GUI
Flask backend exposing all 27 modules via REST API
Run: python app.py   → open http://localhost:5000
"""

import sys, os, json, getpass, threading, uuid, time
from datetime import datetime
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS

from config import (OUTPUT_DIR, GITHUB_TOKEN, OTX_API_KEY, ABUSEIPDB_KEY,
                    SECURITYTRAILS_KEY, ETHERSCAN_KEY, IPQUALITYSCORE_KEY,
                    IPINFO_TOKEN)

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

# ── Flask App ──────────────────────────────────────────────────
app  = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("static", exist_ok=True)

# ── Module Instances ───────────────────────────────────────────
modules = {
    "username_lookup":  UsernameLookup(),
    "domain_intel":     DomainIntel(),
    "phone_lookup":     PhoneLookup(),
    "breach_check":     BreachCheck(),
    "social_media":     SocialMediaScraper(),
    "metadata":         MetadataExtractor(),
    "dorking":          GoogleDorking(),
    "geolocation":      GeoLocation(),
    "monitor":          Monitor(),
    "reporter":         ReportGenerator(OUTPUT_DIR),
    "anonymity":        AnonymityManager(),
    "web_archive":      WebArchive(),
    "github_recon":     GitHubRecon(github_token=GITHUB_TOKEN),
    "paste_monitor":    PasteMonitor(),
    "company_intel":    CompanyIntel(),
    "threat_intel":     ThreatIntel(otx_key=OTX_API_KEY, abuseipdb_key=ABUSEIPDB_KEY),
    "email_header":     EmailHeaderAnalyzer(),
    "reverse_image":    ReverseImageSearch(),
    "crypto_tracer":    CryptoTracer(etherscan_key=ETHERSCAN_KEY),
    "dns_history":      DNSHistory(securitytrails_key=SECURITYTRAILS_KEY),
    "network_intel":    NetworkIntel(ipinfo_token=IPINFO_TOKEN),
    "cloud_discovery":  CloudDiscovery(),
    "web_crawler":      WebCrawler(),
    "ip_classifier":    IPClassifier(ipqs_key=IPQUALITYSCORE_KEY, abuseipdb_key=ABUSEIPDB_KEY),
    "graph_viz":        GraphViz(),
}

# ── Job tracking ───────────────────────────────────────────────
jobs: Dict[str, Any] = {}

def run_job(job_id: str, fn, *args, **kwargs):
    jobs[job_id]["status"] = "running"
    jobs[job_id]["started"] = datetime.now().isoformat()
    try:
        result = fn(*args, **kwargs)
        jobs[job_id]["result"] = result
        jobs[job_id]["status"] = "done"
    except Exception as e:
        jobs[job_id]["status"]  = "error"
        jobs[job_id]["error"]   = str(e)
    jobs[job_id]["finished"] = datetime.now().isoformat()

def start_job(fn, *args, **kwargs) -> str:
    jid = str(uuid.uuid4())
    jobs[jid] = {"status": "queued", "id": jid, "result": None}
    t = threading.Thread(target=run_job, args=(jid, fn, *args), kwargs=kwargs, daemon=True)
    t.start()
    return jid

# ── Routes ─────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def status():
    return jsonify({"status": "online", "modules": len(modules),
                    "timestamp": datetime.now().isoformat()})

@app.route("/api/anonymity")
def anonymity():
    return jsonify(modules["anonymity"].status_report())

# Job polling
@app.route("/api/job/<job_id>")
def job_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

# ── Module Endpoints ───────────────────────────────────────────
def _jresp(fn, *a, **kw):
    """Start async job and return job_id."""
    jid = start_job(fn, *a, **kw)
    return jsonify({"job_id": jid, "status": "queued"})

@app.route("/api/username", methods=["POST"])
def username():
    t = request.json.get("target","").strip()
    fn = modules["username_lookup"].investigate_email if "@" in t else modules["username_lookup"].search_username
    return _jresp(fn, t)

@app.route("/api/domain", methods=["POST"])
def domain():
    t = request.json.get("target","").strip()
    def run(d):
        return {
            "whois": modules["domain_intel"].whois_lookup(d),
            "dns":   modules["domain_intel"].dns_lookup(d),
            "ssl":   modules["domain_intel"].ssl_certificate_info(d),
            "subs":  modules["domain_intel"].enumerate_subdomains(d),
            "tech":  modules["domain_intel"].fingerprint_technologies(d),
            "geo":   modules["geolocation"].domain_geolocation(d),
        }
    return _jresp(run, t)

@app.route("/api/ip", methods=["POST"])
def ip():
    t = request.json.get("target","").strip()
    def run(ip):
        return {
            "lookup": modules["domain_intel"].ip_lookup(ip),
            "geo":    modules["geolocation"].ip_geolocation(ip),
            "asn":    modules["network_intel"].ip_to_asn(ip),
            "rdap":   modules["network_intel"].rdap_lookup(ip),
            "classify": modules["ip_classifier"].classify(ip),
            "threat": modules["threat_intel"].ip_reputation(ip),
        }
    return _jresp(run, t)

@app.route("/api/phone", methods=["POST"])
def phone():
    t = request.json.get("target","").strip()
    return _jresp(modules["phone_lookup"].lookup, t)

@app.route("/api/breach", methods=["POST"])
def breach():
    t = request.json.get("target","").strip()
    return _jresp(modules["breach_check"].check_email, t)

@app.route("/api/password", methods=["POST"])
def password():
    pw = request.json.get("password","")
    return _jresp(modules["breach_check"].check_password, pw)

@app.route("/api/social", methods=["POST"])
def social():
    t = request.json.get("target","").strip()
    return _jresp(modules["social_media"].full_social_scan, t)

@app.route("/api/metadata", methods=["POST"])
def metadata():
    t = request.json.get("target","").strip()
    return _jresp(modules["metadata"].extract, t)

@app.route("/api/dork", methods=["POST"])
def dork():
    data = request.json
    t    = data.get("target","").strip()
    exe  = data.get("execute", False)
    fn   = modules["dorking"].run_dork_campaign if exe else modules["dorking"].generate_dorks
    return _jresp(fn, t)

@app.route("/api/geo", methods=["POST"])
def geo():
    t = request.json.get("target","").strip()
    import re, socket
    if re.match(r"^[-+]?\d+\.?\d*,\s*[-+]?\d+\.?\d*$", t):
        lat, lon = map(float, t.split(","))
        return _jresp(modules["geolocation"].reverse_geocode, lat, lon)
    try:
        socket.inet_aton(t)
        return _jresp(modules["geolocation"].ip_geolocation, t)
    except Exception:
        return _jresp(modules["geolocation"].domain_geolocation, t)

@app.route("/api/archive", methods=["POST"])
def archive():
    data = request.json
    t    = data.get("target","").strip()
    snap = data.get("snapshot", False)
    ts   = data.get("timestamp", None)
    if snap:
        return _jresp(modules["web_archive"].extract_snapshot_content, t, ts)
    return _jresp(modules["web_archive"].domain_timeline, t)

@app.route("/api/github", methods=["POST"])
def github():
    data = request.json
    t    = data.get("target","").strip()
    scan = data.get("scan_secrets", False)
    if "/" in t:
        return _jresp(modules["github_recon"].scan_repo_for_secrets, t)
    if "." in t:
        return _jresp(modules["github_recon"].search_domain_exposure, t)
    return _jresp(modules["github_recon"].user_recon, t)

@app.route("/api/paste", methods=["POST"])
def paste():
    data = request.json
    q    = data.get("query","").strip()
    url  = data.get("url","").strip() or None
    if url:
        return _jresp(modules["paste_monitor"].analyze_paste, url)
    return _jresp(modules["paste_monitor"].search_all, q)

@app.route("/api/company", methods=["POST"])
def company():
    t = request.json.get("target","").strip()
    return _jresp(modules["company_intel"].full_company_profile, t)

@app.route("/api/threat", methods=["POST"])
def threat():
    data = request.json
    ioc  = data.get("target","").strip()
    ioc_type = data.get("ioc_type","auto")
    import re
    if ioc_type == "auto":
        if re.match(r"\b[a-fA-F0-9]{32,64}\b", ioc): ioc_type = "hash"
        elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ioc): ioc_type = "ip"
        elif ioc.startswith("http"): ioc_type = "url"
        else: ioc_type = "domain"
    fns = {
        "ip":     modules["threat_intel"].ip_reputation,
        "domain": modules["threat_intel"].domain_reputation,
        "hash":   modules["threat_intel"].file_hash_lookup,
        "url":    modules["threat_intel"].url_analysis,
    }
    return _jresp(fns.get(ioc_type, modules["threat_intel"].domain_reputation), ioc)

@app.route("/api/email_header", methods=["POST"])
def email_header():
    raw = request.json.get("headers","").strip()
    if not raw:
        return jsonify({"error": "No headers provided"}), 400
    return _jresp(modules["email_header"].analyze, raw)

@app.route("/api/image", methods=["POST"])
def image():
    t = request.json.get("target","").strip()
    return _jresp(modules["reverse_image"].analyze_image, t)

@app.route("/api/crypto", methods=["POST"])
def crypto():
    t = request.json.get("target","").strip()
    return _jresp(modules["crypto_tracer"].lookup, t)

@app.route("/api/dns_history", methods=["POST"])
def dns_history():
    t = request.json.get("target","").strip()
    return _jresp(modules["dns_history"].full_history, t)

@app.route("/api/network", methods=["POST"])
def network():
    t = request.json.get("target","").strip()
    import re
    if re.match(r"^[Aa][Ss]\d+$|^\d{1,6}$", t):
        return _jresp(modules["network_intel"].asn_lookup, t)
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", t):
        def run(ip):
            return {
                "asn":   modules["network_intel"].ip_to_asn(ip),
                "rdap":  modules["network_intel"].rdap_lookup(ip),
                "ports": modules["network_intel"].quick_port_check(ip),
            }
        return _jresp(run, t)
    return _jresp(modules["network_intel"].org_ip_ranges, t)

@app.route("/api/cloud", methods=["POST"])
def cloud():
    t = request.json.get("target","").strip()
    return _jresp(modules["cloud_discovery"].full_cloud_scan, t)

@app.route("/api/crawl", methods=["POST"])
def crawl():
    data = request.json
    t    = data.get("target","").strip()
    mp   = int(data.get("max_pages", 30))
    quick = data.get("quick", False)
    if quick:
        return _jresp(modules["web_crawler"].scrape_page, t)
    crawler = WebCrawler(max_pages=mp)
    return _jresp(crawler.crawl, t)

@app.route("/api/classify_ip", methods=["POST"])
def classify_ip():
    t = request.json.get("target","").strip()
    return _jresp(modules["ip_classifier"].classify, t)

@app.route("/api/graph", methods=["POST"])
def graph():
    data = request.json
    target = data.get("target","").strip()
    osint_data = data.get("osint_data", {})
    def build(t, od):
        gv = GraphViz()
        gv.build_from_osint(t, od)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(c for c in t if c.isalnum() or c in "-_.")
        path = os.path.join(OUTPUT_DIR, f"graph_{safe}_{ts}.html")
        gv.export_html(path, title=f"OSINT Graph — {t}")
        return {"stats": gv.get_stats(), "output_path": path}
    return _jresp(build, target, osint_data)

@app.route("/api/full", methods=["POST"])
def full():
    data   = request.json
    target = data.get("target","").strip()
    fmts   = data.get("formats", ["html","json"])

    def full_scan(t, formats):
        import socket
        results = {"target": t, "timestamp": datetime.now().isoformat()}
        is_email  = "@" in t
        is_ip = False
        try: socket.inet_aton(t); is_ip = True
        except Exception: pass
        is_domain = not is_email and not is_ip and "." in t

        if is_email:
            steps = [
                ("email_lookup",  lambda: modules["username_lookup"].investigate_email(t)),
                ("breach_check",  lambda: modules["breach_check"].check_email(t)),
                ("paste_search",  lambda: modules["paste_monitor"].search_all(t)),
            ]
        elif is_ip:
            steps = [
                ("ip_intel",      lambda: modules["domain_intel"].ip_lookup(t)),
                ("threat_intel",  lambda: modules["threat_intel"].ip_reputation(t)),
                ("ip_classifier", lambda: modules["ip_classifier"].classify(t)),
                ("geolocation",   lambda: modules["geolocation"].ip_geolocation(t)),
            ]
        elif is_domain:
            steps = [
                ("domain_intel",  lambda: {"whois": modules["domain_intel"].whois_lookup(t),
                                            "dns":   modules["domain_intel"].dns_lookup(t),
                                            "ssl":   modules["domain_intel"].ssl_certificate_info(t)}),
                ("dns_history",   lambda: modules["dns_history"].hackertarget_dns_lookup(t)),
                ("cloud_assets",  lambda: modules["cloud_discovery"].full_cloud_scan(t)),
                ("threat_intel",  lambda: modules["threat_intel"].domain_reputation(t)),
                ("web_archive",   lambda: modules["web_archive"].domain_timeline(t)),
            ]
        else:
            steps = [
                ("username",      lambda: modules["username_lookup"].search_username(t)),
                ("social_media",  lambda: modules["social_media"].full_social_scan(t)),
                ("github_recon",  lambda: modules["github_recon"].user_recon(t)),
                ("paste_search",  lambda: modules["paste_monitor"].search_all(t)),
            ]

        for name, fn in steps:
            try:    results[name] = fn()
            except Exception as e: results[name] = {"error": str(e)}

        files = modules["reporter"].full_report(results, t, formats=formats)
        results["report_files"] = files
        return results

    return _jresp(full_scan, target, fmts)

@app.route("/api/reports")
def list_reports():
    files = []
    for f in os.listdir(OUTPUT_DIR):
        if f.endswith((".html",".json")) and not f.endswith("osint_tool.log"):
            stat = os.stat(os.path.join(OUTPUT_DIR, f))
            files.append({
                "name": f,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "url": f"/output/{f}",
            })
    files.sort(key=lambda x: x["modified"], reverse=True)
    return jsonify(files)

@app.route("/output/<path:filename>")
def serve_output(filename):
    return send_from_directory(OUTPUT_DIR, filename)

if __name__ == "__main__":
    print("\n" + "═"*55)
    print("  OSINT Tool v2.0 — Web GUI")
    print("  http://localhost:5000")
    print("═"*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

# ── Import new v3.0 modules ───────────────────────────────────
from config import (HYBRID_ANALYSIS_KEY, WIGLE_KEY, CENSYS_API_ID,
                    CENSYS_API_SECRET, MARINETRAFFIC_KEY,
                    SLACK_WEBHOOK, DISCORD_WEBHOOK, USE_TOR, TOR_PROXY)
from modules.malware_analysis  import MalwareAnalysis
from modules.darkweb_intel     import DarkWebIntel
from modules.cert_transparency import CertTransparency
from modules.wireless_intel    import WirelessIntel
from modules.physical_intel    import PhysicalIntel
from modules.financial_intel   import FinancialIntel
from modules.career_intel      import CareerIntel
from modules.workflow          import Workflow

# Instantiate new modules
modules["malware"]    = MalwareAnalysis(hybrid_key=HYBRID_ANALYSIS_KEY)
modules["darkweb"]    = DarkWebIntel(use_tor=USE_TOR, tor_proxy=TOR_PROXY)
modules["cert_trans"] = CertTransparency(censys_id=CENSYS_API_ID,
                                          censys_secret=CENSYS_API_SECRET)
modules["wireless"]   = WirelessIntel(wigle_key=WIGLE_KEY)
modules["physical"]   = PhysicalIntel(marinetraffic_key=MARINETRAFFIC_KEY)
modules["financial"]  = FinancialIntel()
modules["career"]     = CareerIntel()
modules["workflow"]   = Workflow(modules_dict=modules)

# ── New v3.0 endpoints ────────────────────────────────────────

@app.route("/api/malware", methods=["POST"])
def malware():
    data = request.json
    t    = data.get("target","").strip()
    mode = data.get("mode","full")
    def run(target, m):
        if m == "strings":
            return modules["malware"].extract_strings(target)
        elif m == "pe":
            return modules["malware"].analyze_pe(target)
        elif m == "yara":
            return modules["malware"].yara_quick_scan(target)
        elif m == "hash":
            return modules["malware"].hash_file(target)
        else:
            return modules["malware"].full_analysis(target)
    return _jresp(run, t, mode)

@app.route("/api/darkweb", methods=["POST"])
def darkweb():
    data  = request.json
    t     = data.get("target","").strip()
    mode  = data.get("mode","full")
    def run(target, m):
        if m == "ahmia":
            return modules["darkweb"].ahmia_search(target)
        elif m == "ransomware":
            return modules["darkweb"].ransomware_leak_search(target)
        elif m == "paste":
            return modules["darkweb"].dark_paste_search(target)
        else:
            return modules["darkweb"].full_profile(target)
    return _jresp(run, t, mode)

@app.route("/api/cert_transparency", methods=["POST"])
def cert_transparency():
    data = request.json
    t    = data.get("target","").strip()
    mode = data.get("mode","full")
    def run(target, m):
        if m == "typosquats":
            return modules["cert_trans"].find_suspicious_certs(target)
        elif m == "org":
            return modules["cert_trans"].org_cert_search(target)
        else:
            return modules["cert_trans"].full_report(target)
    return _jresp(run, t, mode)

@app.route("/api/wireless", methods=["POST"])
def wireless():
    t = request.json.get("target","").strip()
    return _jresp(modules["wireless"].full_wireless_profile, t)

@app.route("/api/physical", methods=["POST"])
def physical():
    data = request.json
    t    = data.get("target","").strip()
    mode = data.get("mode","auto")
    def run(target, m):
        import re
        if m == "vin" or re.match(r"^[A-HJ-NPR-Z0-9]{17}$", target.upper()):
            return modules["physical"].decode_vin(target)
        elif m == "aircraft" or target.upper().startswith("N"):
            return modules["physical"].faa_aircraft_lookup(target)
        elif m == "vessel":
            return modules["physical"].vessel_lookup(target)
        elif m == "icao":
            return modules["physical"].opensky_aircraft_track(target)
        else:
            return modules["physical"].decode_vin(target)
    return _jresp(run, t, mode)

@app.route("/api/financial", methods=["POST"])
def financial():
    data = request.json
    t    = data.get("target","").strip()
    mode = data.get("mode","full")
    def run(target, m):
        if m == "ofac":
            return modules["financial"].ofac_check(target)
        elif m == "offshore":
            return modules["financial"].icij_offshore_search(target)
        elif m == "insider":
            return modules["financial"].sec_insider_trading(target)
        elif m == "ownership":
            return modules["financial"].beneficial_ownership(target)
        else:
            return modules["financial"].full_financial_profile(target)
    return _jresp(run, t, mode)

@app.route("/api/career", methods=["POST"])
def career():
    data = request.json
    t    = data.get("target","").strip()
    mode = data.get("mode","company")
    def run(target, m):
        if m == "jobs":
            return modules["career"].scrape_job_postings(target)
        elif m == "h1b":
            return modules["career"].h1b_search(target)
        elif m == "patents":
            return modules["career"].patent_search(target)
        else:
            is_company = m == "company"
            return modules["career"].full_career_profile(target, is_company=is_company)
    return _jresp(run, t, mode)

@app.route("/api/workflow/playbooks")
def workflow_list():
    return jsonify(modules["workflow"].list_playbooks())

@app.route("/api/workflow/run", methods=["POST"])
def workflow_run():
    data       = request.json
    playbook   = data.get("playbook","email_full")
    target     = data.get("target","").strip()
    webhook_url= data.get("webhook_url","")
    def run(pb, t, wh):
        result = modules["workflow"].run_playbook(pb, t, output_dir=OUTPUT_DIR)
        if wh:
            modules["workflow"].send_webhook(wh, result)
        return result
    return _jresp(run, playbook, target, webhook_url)
