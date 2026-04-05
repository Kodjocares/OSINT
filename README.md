<div align="center">

```
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
              v3.0 — 35 Modules
```

**Open Source Intelligence Framework · Python 3.9+**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-22863a?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-35-00d4ff?style=flat-square)](#modules)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff6b35?style=flat-square)](CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-3fb950?style=flat-square)]()
[![GitHub Stars](https://img.shields.io/github/stars/YOUR_USERNAME/osint-tool?style=flat-square&color=f0b429)](https://github.com/YOUR_USERNAME/osint-tool/stargazers)

**A modular, extensible OSINT framework with 27 intelligence modules — username enumeration, breach detection, threat intelligence, blockchain tracing, cloud asset discovery, entity graph visualization, and much more.**

[Installation](#installation) · [Usage](#usage) · [Modules](#modules) · [API Keys](#api-keys) · [Contributing](#contributing)

---

> ⚠️ **For authorized security research and ethical OSINT investigations only.**
> You are solely responsible for ensuring your use complies with all applicable laws.

</div>

---

## What is OSINT Tool?

OSINT Tool is a comprehensive, modular Python framework for Open Source Intelligence gathering. It consolidates 27 specialized modules under a single interactive CLI and produces professional HTML reports, JSON exports, and interactive entity-relationship graphs.

Whether you're an independent security researcher, a penetration tester, a digital forensics analyst, or a journalist investigating public records — OSINT Tool provides a structured, repeatable workflow from a single terminal command.

**Key design principles:**
- Every module works standalone or as part of a full investigation
- Graceful degradation — all API keys are optional; free sources work without registration
- Privacy-respecting — passwords are checked via k-anonymity and never transmitted
- Tor-compatible — route all traffic through Tor with one config line
- Report-first — every run produces structured JSON + styled HTML output

---

## Modules

### Original Modules

| # | Module | File | Capabilities |
|---|--------|------|-------------|
| 1 | **Username / Email** | `username_lookup.py` | Enumerate 30+ platforms in parallel; email MX, Gravatar, Hunter.io |
| 2 | **Domain & IP Intel** | `domain_intel.py` | WHOIS, full DNS, subdomain enum (crt.sh + bruteforce), SSL cert, Shodan, VirusTotal, tech fingerprinting |
| 3 | **Phone Tracking** | `phone_lookup.py` | E.164 parsing, carrier, line type, region; AbstractAPI + NumVerify |
| 4 | **Breach Check** | `breach_check.py` | HaveIBeenPwned email breach lookup, paste exposure |
| 5 | **Password Exposure** | `breach_check.py` | k-anonymity SHA-1 check — password never transmitted |
| 6 | **Social Media** | `social_media.py` | GitHub full API (repos/orgs/events), Reddit API, generic scraper |
| 7 | **Metadata Extraction** | `metadata_extractor.py` | EXIF/GPS from images, PDF author info, DOCX user metadata |
| 8 | **Google Dorking** | `google_dorking.py` | 15+ dork categories, custom operator builder, DDG execution |
| 9 | **Geolocation** | `geolocation.py` | IP/domain/GPS geolocation, reverse geocoding, Folium HTML maps |
| 10 | **Monitoring & Alerts** | `monitoring.py` | SHA-256 change detection, email alerts, background scheduler |

### New Modules (v2.0)

| # | Module | File | Capabilities |
|---|--------|------|-------------|
| 11 | **Web Archive** | `web_archive.py` | Wayback Machine snapshots, domain timeline, deleted content extraction, snapshot diff |
| 12 | **GitHub Recon** | `github_recon.py` | Secret pattern scanning (30+ regex), commit email harvest, domain/org code exposure |
| 13 | **Paste Monitor** | `paste_monitor.py` | Search Pastebin/Ghostbin/Gist/Rentry; auto-classify as credential dump, hash dump, or financial data |
| 14 | **Company Intel** | `company_intel.py` | OpenCorporates registrations + officers, SEC EDGAR filings, LinkedIn job posting scraping |
| 15 | **Threat Intelligence** | `threat_intel.py` | AlienVault OTX, VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus — IP/domain/hash/URL |
| 16 | **Email Header Analysis** | `email_header.py` | Hop chain reconstruction, spoofing detection, SPF/DKIM/DMARC, sender IP geolocation |
| 17 | **Reverse Image Search** | `reverse_image.py` | Search URL generation (Google/Yandex/TinEye/Bing), OCR text extraction, image hashing |
| 18 | **Crypto Tracer** | `crypto_tracer.py` | Bitcoin & Ethereum balance/transactions, Blockchair multi-chain, wallet risk classification |
| 19 | **DNS History** | `dns_history.py` | HackerTarget passive DNS (free), SecurityTrails history, ViewDNS IP history, reverse IP |
| 20 | **ASN / Network Intel** | `network_intel.py` | BGPView ASN details, IP→ASN, org IP ranges, RDAP registration, quick port check |
| 21 | **Cloud Asset Discovery** | `cloud_discovery.py` | S3/Azure Blob/GCS bucket enum (30+ permutations), Firebase exposure check |
| 22 | **Web Crawler** | `web_crawler.py` | Full site spider, form extraction, login/admin page detection, bulk email/phone harvest |
| 23 | **IP Classifier** | `ip_classifier.py` | Tor exit node list, VPN/proxy/datacenter/residential detection (IPQualityScore + AbuseIPDB) |
| 24 | **Graph Visualization** | `graph_viz.py` | Interactive D3.js entity-relationship graph, auto-built from any OSINT result, pyvis/NetworkX export |

### New Categories (v3.0)

| # | Module | File | Capabilities |
|---|--------|------|-------------|
| 27 | **Malware Analysis** | `malware_analysis.py` | PE headers, string extraction, YARA signatures, VirusTotal sandbox, Hybrid Analysis |
| 28 | **Dark Web Intel** | `darkweb_intel.py` | Ahmia search, ransomware leak trackers (RansomWatch + ransomware.live), dark pastes |
| 29 | **Cert Transparency** | `cert_transparency.py` | crt.sh subdomain history, org search, typosquat detection, cert timeline |
| 30 | **WiFi / Bluetooth** | `wireless_intel.py` | WiGLE SSID/BSSID geolocation, MAC vendor lookup, Bluetooth device classification |
| 31 | **Vehicle & Physical** | `physical_intel.py` | VIN decode (NHTSA), FAA aircraft lookup, OpenSky live tracking, vessel search |
| 32 | **Financial Intel** | `financial_intel.py` | OFAC sanctions (OpenSanctions), ICIJ offshore leaks, SEC Form 4, beneficial ownership |
| 33 | **Career Intel** | `career_intel.py` | Job postings, H-1B visa data, USPTO patents, historical job ad recovery |
| 34 | **Playbook Runner** | `workflow.py` | 6 built-in playbooks, bulk CSV processing, Slack/Discord/Teams webhook alerts |

### Support Modules

| Module | File | Purpose |
|--------|------|---------|
| **Anonymity** | `utils/anonymity.py` | Tor via stem, proxy rotation, DNS leak check, identity verification |
| **HTTP Client** | `utils/helpers.py` | Rate limiting, retry logic, user-agent rotation |
| **Report Generator** | `reporting/report_generator.py` | Dark-themed HTML reports, JSON export, matplotlib charts |

---

## Project Structure

```
osint-tool/
├── main.py                        # CLI entry point & interactive menu (27 options)
├── config.py                      # All API keys, settings, platform lists
├── .env.example                   # Environment variables template
├── requirements.txt               # Runtime dependencies
├── requirements-dev.txt           # Dev/test dependencies
├── pyproject.toml                 # Package metadata & build config
│
├── modules/                       # Intelligence modules
│   ├── username_lookup.py
│   ├── domain_intel.py
│   ├── phone_lookup.py
│   ├── breach_check.py
│   ├── social_media.py
│   ├── metadata_extractor.py
│   ├── google_dorking.py
│   ├── geolocation.py
│   ├── monitoring.py
│   ├── web_archive.py             # NEW
│   ├── github_recon.py            # NEW
│   ├── paste_monitor.py           # NEW
│   ├── company_intel.py           # NEW
│   ├── threat_intel.py            # NEW
│   ├── email_header.py            # NEW
│   ├── reverse_image.py           # NEW
│   ├── crypto_tracer.py           # NEW
│   ├── dns_history.py             # NEW
│   ├── network_intel.py           # NEW
│   ├── cloud_discovery.py         # NEW
│   ├── web_crawler.py             # NEW
│   ├── ip_classifier.py           # NEW
│   └── graph_viz.py               # NEW
│
├── reporting/
│   └── report_generator.py        # HTML/JSON reports + charts
│
├── utils/
│   ├── helpers.py                 # HTTP client, rate limiting
│   └── anonymity.py               # Tor & proxy management
│
├── tests/
│   └── test_modules.py            # pytest test suite
│
├── output/                        # Generated reports (git-ignored)
├── wordlists/                     # Custom wordlists (git-ignored)
│
└── .github/
    ├── workflows/
    │   ├── ci.yml                 # Lint, test, security scan
    │   └── release.yml            # Auto-release on tag push
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── feature_request.md
    └── PULL_REQUEST_TEMPLATE.md
```

---

## Installation

### Requirements

- Python **3.9** or higher
- `pip` + `venv`
- Tor *(optional — for anonymous routing)*
- Tesseract OCR *(optional — for image text extraction)*

### Step 1 — Clone

```bash
git clone https://github.com/Kodjocares/osint.git
cd osint-tool
```

### Step 2 — Virtual environment

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Configure API keys

```bash
cp .env.example .env
# Open .env and add your API keys — all are optional
```

### Step 5 — Verify

```bash
python main.py --anonymity
```

---

## Usage

### Interactive Menu

```bash
python main.py
```

```
╔══════════════════════════════════════════════════════════╗
║            OSINT INTELLIGENCE TOOL v2.0                  ║
╠══════════════════════════════════════════════════════════╣
║  ORIGINAL MODULES                                        ║
║  [1]  Username / Email Lookup     [2]  Domain & IP       ║
║  [3]  Phone Tracking              [4]  Breach Check      ║
║  [5]  Password Exposure           [6]  Social Media      ║
║  [7]  Metadata Extraction         [8]  Google Dorks      ║
║  [9]  Geolocation                 [10] Monitoring        ║
╠══════════════════════════════════════════════════════════╣
║  NEW MODULES                                             ║
║  [11] Web Archive / Wayback       [12] GitHub Recon      ║
║  [13] Paste Site Monitor          [14] Company Intel     ║
║  [15] Threat Intelligence / IOC   [16] Email Header      ║
║  [17] Reverse Image Search        [18] Crypto Trace      ║
║  [19] DNS History                 [20] ASN / Network     ║
║  [21] Cloud Asset Discovery       [22] Web Crawler       ║
║  [23] IP Classifier               [24] Graph Viz         ║
╠══════════════════════════════════════════════════════════╣
║  [25] Full Target Investigation   [26] Anonymity         ║
╚══════════════════════════════════════════════════════════╝
```

---

## Command-Line Reference

### Original Modules

```bash
# Username — scan 30+ platforms
python main.py --username johndoe

# Email — MX records, Gravatar, Hunter.io
python main.py --email target@example.com

# Domain — WHOIS + DNS + subdomains + SSL + tech stack + geo
python main.py --domain example.com

# IP — reverse DNS + Shodan + VirusTotal + geolocation
python main.py --ip 8.8.8.8

# Phone — carrier, line type, region (E.164 format)
python main.py --phone "+14155552671"

# Email breach check (HaveIBeenPwned)
python main.py --breach user@example.com

# Password exposure — k-anonymity, password NEVER transmitted
python main.py --password-check

# Social media scrape (GitHub + Reddit public data)
python main.py --social johndoe

# Metadata extraction — images, PDFs, DOCX; local or URL
python main.py --metadata /path/to/photo.jpg
python main.py --metadata https://example.com/doc.pdf

# Google dork generation
python main.py --dork example.com
python main.py --dork example.com --dork-execute

# Geolocation — IP, domain, or GPS coords
python main.py --geo 8.8.8.8
python main.py --geo "37.7749,-122.4194"
```

### New Modules (v2.0)

```bash
# Web Archive — Wayback Machine timeline
python main.py --archive example.com
python main.py --archive https://example.com/page --archive-snapshot
python main.py --archive https://example.com --archive-ts 20200101120000

# GitHub Recon — profile, repos, commit emails
python main.py --github johndoe
python main.py --github johndoe --scan-secrets
python main.py --github org/repository --scan-secrets  # deep secret scan

# Paste Site Monitor — search Pastebin, Gist, Ghostbin, etc.
python main.py --paste "user@example.com"
python main.py --paste "example.com"
python main.py --paste-url https://pastebin.com/AbCdEfGh

# Company Intelligence — registrations, SEC filings, job postings
python main.py --company "Acme Corporation"
python main.py --company "Tesla Inc"

# Threat Intelligence — IP, domain, file hash, URL
python main.py --threat 8.8.8.8
python main.py --threat example.com
python main.py --threat d41d8cd98f00b204e9800998ecf8427e   # MD5 hash
python main.py --threat https://malicious-site.example.com --ioc-type url

# Email Header Analysis — detect spoofing, trace origin
python main.py --email-header /path/to/raw_headers.txt

# Reverse Image Search — generate search URLs + OCR
python main.py --image https://example.com/photo.jpg
python main.py --image /path/to/local/image.jpg

# Cryptocurrency tracing — Bitcoin and Ethereum
python main.py --crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf
python main.py --crypto 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

# DNS History — passive DNS, IP history, reverse IP
python main.py --dns-history example.com

# ASN / Network Intelligence
python main.py --asn AS15169            # Google's ASN
python main.py --asn 8.8.8.8            # Auto-resolve IP to ASN
python main.py --asn "Cloudflare Inc"   # Org name search

# Cloud Asset Discovery — S3, Azure, GCS, Firebase
python main.py --cloud example.com

# Web Crawler — spider entire site
python main.py --crawl https://example.com
python main.py --crawl https://example.com --max-pages 100
python main.py --crawl https://example.com/page --quick-scrape

# IP Classifier — VPN, Tor, proxy, datacenter, residential
python main.py --classify-ip 8.8.8.8
python main.py --classify-ip 185.220.101.1

# Entity Relationship Graph
python main.py --graph target@example.com
python main.py --graph target@example.com --graph-data output/results.json

# Full Automated Investigation (all relevant modules + graph)
python main.py --full target@example.com
python main.py --full example.com --output html,json
python main.py --full 1.2.3.4
python main.py --full johndoe

# Anonymity / Tor status
python main.py --anonymity
```

### Output Files

Every run saves results to `output/`:

```
output/
├── example_com_20240315_143022.html      # Styled HTML report
├── example_com_20240315_143022.json      # Full JSON data export
├── graph_example_com_20240315.html       # Interactive entity graph
├── breach_chart.png                      # Matplotlib breach chart
├── geo_map.html                          # Folium geolocation map
├── osint_tool.log                        # Execution log
└── alerts/                               # Monitoring change alerts
```

---

## API Keys Reference

> All API keys are **optional**. The tool degrades gracefully — modules that require a key skip that enrichment step and still return data from free sources. Password checks via HIBP are always free with no key required.

| Service | Module | Free Tier | Sign Up |
|---------|--------|-----------|---------|
| [Shodan](https://shodan.io) | Domain & IP | Yes — limited | [account.shodan.io](https://account.shodan.io/register) |
| [VirusTotal](https://virustotal.com) | Domain, IP, Threat Intel | Yes — 4 req/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| [Hunter.io](https://hunter.io) | Email lookup | Yes — 25/month | [hunter.io](https://hunter.io/users/sign_up) |
| [IPInfo](https://ipinfo.io) | Geolocation | Yes — 50k/month | [ipinfo.io](https://ipinfo.io/signup) |
| [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | Breach check | Paid — $3.50/mo | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) |
| [AbstractAPI](https://abstractapi.com) | Phone | Yes | [app.abstractapi.com](https://app.abstractapi.com/users/signup) |
| [NumVerify](https://numverify.com) | Phone | Yes — 250/month | [numverify.com](https://numverify.com) |
| [Google CSE](https://programmablesearchengine.google.com) | Dork execution | Yes — 100/day | [programmablesearchengine.google.com](https://programmablesearchengine.google.com) |
| [GitHub](https://github.com/settings/tokens) | GitHub Recon | Yes — free | [github.com/settings/tokens](https://github.com/settings/tokens) |
| [AlienVault OTX](https://otx.alienvault.com) | Threat Intel | Yes — free | [otx.alienvault.com](https://otx.alienvault.com) |
| [AbuseIPDB](https://www.abuseipdb.com/register) | Threat Intel, IP Classifier | Yes — 1k/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| [SecurityTrails](https://securitytrails.com) | DNS History | Yes — 50/month | [securitytrails.com](https://securitytrails.com/corp/api) |
| [Etherscan](https://etherscan.io/apis) | Crypto Tracer | Yes — free | [etherscan.io/apis](https://etherscan.io/apis) |
| [IPQualityScore](https://ipqualityscore.com) | IP Classifier | Yes — 200/day | [ipqualityscore.com](https://www.ipqualityscore.com/create-account) |
| [TinEye](https://tineye.com/api) | Reverse Image | Paid | [tineye.com/api](https://services.tineye.com/TinEyeAPI) |

**No API key required for:** password checks (HIBP k-anonymity), crt.sh subdomain enumeration, ip-api.com geolocation, DNS lookups, WHOIS, SSL checks, GitHub/Reddit public API, DuckDuckGo search, Wayback Machine, OpenCorporates (basic), HackerTarget passive DNS, BGPView ASN lookups, Tor exit node list, Blockchain.info BTC lookups, AlienVault OTX (limited), URLhaus, MalwareBazaar.

---

## Anonymity with Tor

### Install Tor

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install tor
sudo service tor start

# macOS
brew install tor
brew services start tor

# Verify
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### Enable in `.env`

```env
USE_TOR=true
TOR_PROXY=socks5h://127.0.0.1:9050
TOR_CONTROL_PORT=9051
TOR_CONTROL_PASSWORD=your_control_password   # optional
```

### Verify anonymity

```bash
python main.py --anonymity
```

---

## Continuous Monitoring

Register targets for automated change detection:

```python
from modules.monitoring import Monitor
from modules.domain_intel import DomainIntel
import threading

monitor = Monitor()
intel   = DomainIntel()

# Register
monitor.register_target("corp-domain", "domain", "example.com",
                         description="Watch for DNS/WHOIS changes")

# One-off check
result = monitor.check_target("corp-domain", intel.whois_lookup,
                               domain="example.com")
print(f"Changed: {result['changed']}")

# Background scheduler (every 24h)
t = threading.Thread(
    target=monitor.start_scheduler,
    args=("corp-domain", intel.whois_lookup),
    kwargs={"domain": "example.com"},
    daemon=True
)
t.start()
```

Email alerts in `.env`:

```env
ALERT_EMAIL=you@example.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_gmail@gmail.com
SMTP_PASS=your_app_password
MONITOR_INTERVAL_HOURS=24
```

---

## Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=modules --cov=utils --cov=reporting --cov-report=term-missing

# Single test class
pytest tests/test_modules.py::TestBreachCheck -v

# Lint
flake8 . --max-line-length=100
black --check .

# Security scan
bandit -r modules/ utils/ reporting/ main.py
```

---

## Optional System Dependencies

```bash
# Tesseract OCR (for image text extraction in reverse_image module)
# Ubuntu / Debian
sudo apt install tesseract-ocr

# macOS
brew install tesseract

# Then install the Python binding
pip install pytesseract
```

---

## Publishing to GitHub

```bash
cd osint-tool

git init
git add .
git commit -m "feat: initial release — OSINT Tool v2.0 (27 modules)"

# Create repo at github.com → New Repository
git remote add origin https://github.com/YOUR_USERNAME/osint-tool.git
git branch -M main
git push -u origin main

# Tag the first release
git tag -a v2.0.0 -m "v2.0.0 — 27 modules"
git push origin v2.0.0
```

GitHub Actions will automatically run lint + test on every push and PR.

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.

```bash
# Create a feature branch
git checkout -b feat/my-new-module

# Follow the module pattern in modules/
# Add CLI flags in main.py
# Update this README

# Run tests & lint
pytest tests/ -v
flake8 . --max-line-length=100

# Commit with conventional commits
git commit -m "feat(modules): add LinkedIn public profile scraper"
git push origin feat/my-new-module
```

---

## Security

Found a vulnerability in the tool itself? See [SECURITY.md](SECURITY.md) — please disclose privately, not via a public issue.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full version history.

---

## License

[MIT License](LICENSE) with an additional Ethical Use Clause.

By using this tool you agree to only investigate targets for which you have explicit written authorization, comply with all applicable laws, and not use this tool to cause harm to individuals or organizations.

---

<div align="center">
<sub>Built for the security research community · Use responsibly · Star ⭐ if useful</sub>
</div>

---

## Web GUI

Run the full dashboard in your browser:

```bash
# Install GUI dependencies
pip install flask flask-cors

# Launch
python app.py
```

Open **http://localhost:5000** — all 27 modules are available from the dashboard.

**Features:**
- Dark cyberpunk dashboard with sidebar navigation
- Async job system — results stream in without blocking the UI
- JSON result viewer with syntax highlighting
- Reports browser — open any generated HTML report directly
- Anonymity status indicator (Tor check)
- Keyboard shortcut: `Ctrl+Enter` to run any module

The GUI and CLI are fully parallel — use whichever suits your workflow.
