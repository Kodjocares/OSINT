# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [3.0.0] — 2024-04-10

### Added — 8 new intelligence categories

- **`modules/malware_analysis.py`** — Static binary analysis: PE header parsing (architecture, sections, imports, entropy-based packer detection), string extraction with URL/IP/registry/mutex categorisation, YARA-style signature matching (Mimikatz, Cobalt Strike, Metasploit, UPX, etc.), VirusTotal sandbox behaviour report (process creation, file writes, DNS lookups, HTTP requests, MITRE ATT&CK techniques), Hybrid Analysis lookup, MD5/SHA1/SHA256/SHA512 file hashing

- **`modules/darkweb_intel.py`** — Dark web exposure tracking: Ahmia.fi Tor search engine (clearnet accessible), RansomWatch + Ransomware.live victim database search (detects if a target has been listed by ransomware groups), dark paste site search (psbdmp), optional .onion site reachability check when Tor is enabled

- **`modules/cert_transparency.py`** — Certificate Transparency log mining: crt.sh full subdomain history (often finds more than active DNS), organisation-wide certificate search, typosquat/lookalike domain detection (checks 30+ permutations for phishing certs), certificate timeline with yearly breakdown, wildcard certificate detection

- **`modules/wireless_intel.py`** — WiFi & Bluetooth OSINT: MAC/BSSID vendor identification via maclookup.app (free), WiGLE SSID name → physical location search, WiGLE BSSID → GPS coordinates with Google Maps link, Bluetooth device type classification from OUI (audio, fitness tracker, smartphone, peripheral)

- **`modules/physical_intel.py`** — Vehicle & physical asset intelligence: VIN decoder via NHTSA free API (make/model/year/plant/engine/drivetrain + recall check link), FAA aircraft registration lookup (owner, status, airworthiness), OpenSky live & historical aircraft tracking by ICAO24, vessel search via VesselFinder, license plate format analysis

- **`modules/financial_intel.py`** — Financial OSINT: OFAC sanctions check via OpenSanctions consolidated database (covers OFAC SDN, EU, UN, and 40+ other lists), ICIJ Offshore Leaks search (Panama Papers, Pandora Papers, Paradise Papers, Bahamas Leaks), SEC EDGAR Form 4 insider trading filings, beneficial ownership via OpenCorporates, company filings search

- **`modules/career_intel.py`** — Career & employment intelligence: job posting scraper (Indeed + LinkedIn via DDG) with tech stack and org signal inference, H-1B LCA visa filing data (salary and job title public records), USPTO PatentsView patent search by inventor or assignee, historical job posting recovery via Wayback Machine

- **`modules/workflow.py`** — Investigation automation: 6 built-in playbooks (email_full, domain_full, person_full, ip_full, company_full, threat_hunt), bulk CSV target processing with configurable thread pool, webhook notifications to Slack/Discord/Teams/generic endpoints, per-run JSON output files

### Changed

- `main.py` — Updated to v3.0 with 35-module menu, CLI flags for all 8 new modules (`--malware`, `--darkweb`, `--cert-trans`, `--wireless`, `--physical`, `--financial`, `--career`, `--playbook`, `--list-playbooks`), `Workflow` injected with all live module instances
- `app.py` — 10 new REST endpoints added (`/api/malware`, `/api/darkweb`, `/api/cert_transparency`, `/api/wireless`, `/api/physical`, `/api/financial`, `/api/career`, `/api/workflow/playbooks`, `/api/workflow/run`)
- `templates/index.html` — Updated to v3.0: 8 new sidebar entries under "Intelligence" section, 8 new JS module definitions with mode selectors, playbook dropdown, module count updated to 35
- `config.py` — Added HYBRID_ANALYSIS_KEY, WIGLE_KEY, CENSYS_API_ID/SECRET, MARINETRAFFIC_KEY, SLACK_WEBHOOK, DISCORD_WEBHOOK
- `requirements.txt` — Added pefile
- `.env.example` — All new API keys documented

---

## [2.0.0] — 2024-03-15

### Added — 15 new intelligence modules

- **`modules/web_archive.py`** — Wayback Machine timeline, snapshot content extraction, side-by-side snapshot diff via CDX API
- **`modules/github_recon.py`** — GitHub secret scanning with 30+ regex patterns (AWS keys, tokens, private keys, passwords), commit email harvesting, domain/org code exposure search
- **`modules/paste_monitor.py`** — Multi-source paste site search (Pastebin, Ghostbin, Gist, Rentry, Hastebin); auto-classification as credential dump, hash dump, or financial data
- **`modules/company_intel.py`** — OpenCorporates company search + officer lookup, SEC EDGAR filing search, LinkedIn job posting scraper with tech stack inference
- **`modules/threat_intel.py`** — AlienVault OTX pulse search, VirusTotal file/IP/domain/URL analysis, AbuseIPDB reporting, MalwareBazaar hash lookup, URLhaus URL check
- **`modules/email_header.py`** — Raw email header parser: hop chain reconstruction, SPF/DKIM/DMARC extraction, spoofing indicator detection, sender IP geolocation
- **`modules/reverse_image.py`** — Reverse image search URL generation for Google/Yandex/TinEye/Bing/Baidu, Tesseract + OCR.space fallback text extraction, image hashing (MD5/SHA1/SHA256)
- **`modules/crypto_tracer.py`** — Bitcoin address balance/transaction lookup via Blockchain.info, Ethereum via Etherscan, multi-chain via Blockchair, wallet risk flags, auto address type detection
- **`modules/dns_history.py`** — HackerTarget passive DNS (free), SecurityTrails historical records, ViewDNS IP history, reverse IP lookup
- **`modules/network_intel.py`** — BGPView ASN details + prefixes + peers + upstreams, IP-to-ASN resolution, org IP range search, RDAP registration lookup, quick TCP port check
- **`modules/cloud_discovery.py`** — S3/Azure Blob/GCS bucket enumeration with 30+ name permutations, Firebase Realtime Database exposure check
- **`modules/web_crawler.py`** — Recursive site spider with configurable depth and page limits, form extraction and classification, login/admin page detection, bulk email/phone harvest
- **`modules/ip_classifier.py`** — Tor exit node list (live from torproject.org), VPN/proxy/datacenter/residential detection via IPQualityScore + AbuseIPDB, bulk classification
- **`modules/graph_viz.py`** — Interactive D3.js entity-relationship graph (no pyvis required), auto-built from any OSINT result JSON, pyvis + NetworkX + GraphML export

### Changed

- `main.py` — Rewritten with 27 menu items + 27 CLI `--flags`; full investigation now auto-builds entity graph
- `config.py` — Added 8 new API key variables (GitHub, OTX, AbuseIPDB, SecurityTrails, Etherscan, IPQualityScore, TinEye, ViewDNS)
- `requirements.txt` — Added `pyvis`, `networkx`, `PyPDF2`, `python-docx`
- `.env.example` — Added all new API key variables

### Infrastructure

- Added `pyproject.toml` for proper Python packaging
- Added `CHANGELOG.md`
- Added `CODE_OF_CONDUCT.md`
- Added `.github/PULL_REQUEST_TEMPLATE.md`
- Added `.github/workflows/release.yml` — auto-creates GitHub Releases on version tags
- Updated `.github/workflows/ci.yml` — added Python 3.12, bandit security scan, black formatting check

---

## [1.0.0] — 2024-01-10

### Added — Initial release with 10 modules

- **`modules/username_lookup.py`** — Username enumeration across 30+ social platforms in parallel; email MX record lookup, Gravatar check, Hunter.io verification
- **`modules/domain_intel.py`** — WHOIS, full DNS (A/AAAA/MX/NS/TXT/SOA/CNAME), subdomain enumeration via crt.sh Certificate Transparency + DNS brute-force, SSL certificate analysis, Shodan host lookup, VirusTotal reputation, technology fingerprinting
- **`modules/phone_lookup.py`** — Phone number parsing with `phonenumbers`, carrier identification, line type detection, region geocoding; AbstractAPI + NumVerify enrichment
- **`modules/breach_check.py`** — HaveIBeenPwned v3 API email breach and paste lookup; password exposure check via k-anonymity (SHA-1 prefix only transmitted)
- **`modules/social_media.py`** — GitHub public API full profile scrape (repos, orgs, events, languages); Reddit user API; generic public page scraper with email/link extraction
- **`modules/metadata_extractor.py`** — EXIF data extraction from images including GPS coordinates with Google Maps link; PDF metadata (author, creator, producer); DOCX core properties; remote URL support
- **`modules/google_dorking.py`** — 15 dork templates (exposed files, config files, login pages, credentials, API keys, SSH keys, database dumps, subdomains, etc.); custom dork builder; DuckDuckGo execution; Google Custom Search API support
- **`modules/geolocation.py`** — IP geolocation via IPInfo + ip-api.com fallback; domain-to-IP-to-location; GPS reverse geocoding via Nominatim; forward geocoding; interactive Folium HTML map generation
- **`modules/monitoring.py`** — Target registration, SHA-256 based change detection, email alerts via SMTP, JSON alert file fallback, background threading scheduler
- **`utils/anonymity.py`** — Tor integration via `stem` library, proxy rotation, DNS leak detection, real vs Tor IP comparison
- **`reporting/report_generator.py`** — Dark-themed HTML report with full nested data rendering; JSON export; matplotlib breach exposure chart; platform presence pie chart
- `main.py` — Interactive numbered menu + full argparse CLI with `--flags` for every module
- `config.py` — Centralized configuration with python-dotenv

[3.0.0]: https://github.com/YOUR_USERNAME/osint-tool/releases/tag/v3.0.0
[2.0.0]: https://github.com/YOUR_USERNAME/osint-tool/releases/tag/v2.0.0
[1.0.0]: https://github.com/YOUR_USERNAME/osint-tool/releases/tag/v1.0.0
