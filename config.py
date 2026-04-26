"""
OSINT Tool Configuration
========================
Add your API keys here or use a .env file
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────
# API KEYS  (set via .env or environment vars)
# ──────────────────────────────────────────────
SHODAN_API_KEY          = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
HUNTER_IO_API_KEY       = os.getenv("HUNTER_IO_API_KEY", "")
ABSTRACTAPI_PHONE_KEY   = os.getenv("ABSTRACTAPI_PHONE_KEY", "")
IPINFO_TOKEN            = os.getenv("IPINFO_TOKEN", "")
NUMVERIFY_API_KEY       = os.getenv("NUMVERIFY_API_KEY", "")
GOOGLE_API_KEY          = os.getenv("GOOGLE_API_KEY", "")
GOOGLE_CSE_ID           = os.getenv("GOOGLE_CSE_ID", "")

# ── New module API keys ────────────────────────
GITHUB_TOKEN            = os.getenv("GITHUB_TOKEN", "")          # github_recon
OTX_API_KEY             = os.getenv("OTX_API_KEY", "")           # threat_intel (AlienVault)
ABUSEIPDB_KEY           = os.getenv("ABUSEIPDB_KEY", "")         # threat_intel + ip_classifier
SECURITYTRAILS_KEY      = os.getenv("SECURITYTRAILS_KEY", "")    # dns_history
ETHERSCAN_KEY           = os.getenv("ETHERSCAN_KEY", "")         # crypto_tracer
IPQUALITYSCORE_KEY      = os.getenv("IPQUALITYSCORE_KEY", "")    # ip_classifier
TINEYE_KEY              = os.getenv("TINEYE_KEY", "")            # reverse_image
VIEWDNS_KEY             = os.getenv("VIEWDNS_KEY", "")           # dns_history

# ──────────────────────────────────────────────
# ANONYMITY / PROXY SETTINGS
# ──────────────────────────────────────────────
USE_TOR                 = os.getenv("USE_TOR", "false").lower() == "true"
TOR_PROXY               = os.getenv("TOR_PROXY", "socks5h://127.0.0.1:9050")
TOR_CONTROL_PORT        = int(os.getenv("TOR_CONTROL_PORT", "9051"))
TOR_CONTROL_PASSWORD    = os.getenv("TOR_CONTROL_PASSWORD", "")
HTTP_PROXY              = os.getenv("HTTP_PROXY", "")
HTTPS_PROXY             = os.getenv("HTTPS_PROXY", "")

# ──────────────────────────────────────────────
# REQUEST SETTINGS
# ──────────────────────────────────────────────
REQUEST_TIMEOUT         = int(os.getenv("REQUEST_TIMEOUT", "10"))
REQUEST_DELAY           = float(os.getenv("REQUEST_DELAY", "1.5"))   # seconds between requests
MAX_RETRIES             = int(os.getenv("MAX_RETRIES", "3"))
ROTATE_USER_AGENTS      = os.getenv("ROTATE_USER_AGENTS", "true").lower() == "true"

# ──────────────────────────────────────────────
# OUTPUT SETTINGS
# ──────────────────────────────────────────────
OUTPUT_DIR              = os.getenv("OUTPUT_DIR", "output")
LOG_LEVEL               = os.getenv("LOG_LEVEL", "INFO")
REPORT_FORMAT           = os.getenv("REPORT_FORMAT", "html")   # html | pdf | json | all

# ──────────────────────────────────────────────
# MONITORING SETTINGS
# ──────────────────────────────────────────────
MONITOR_INTERVAL_HOURS  = int(os.getenv("MONITOR_INTERVAL_HOURS", "24"))
ALERT_EMAIL             = os.getenv("ALERT_EMAIL", "")
SMTP_HOST               = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT               = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER               = os.getenv("SMTP_USER", "")
SMTP_PASS               = os.getenv("SMTP_PASS", "")

# ──────────────────────────────────────────────
# SOCIAL PLATFORM TARGETS
# ──────────────────────────────────────────────
SOCIAL_PLATFORMS = [
    "https://github.com/{username}",
    "https://twitter.com/{username}",
    "https://www.instagram.com/{username}",
    "https://www.linkedin.com/in/{username}",
    "https://www.reddit.com/user/{username}",
    "https://www.tiktok.com/@{username}",
    "https://www.facebook.com/{username}",
    "https://www.youtube.com/@{username}",
    "https://www.twitch.tv/{username}",
    "https://www.pinterest.com/{username}",
    "https://medium.com/@{username}",
    "https://dev.to/{username}",
    "https://keybase.io/{username}",
    "https://steamcommunity.com/id/{username}",
    "https://www.deviantart.com/{username}",
    "https://soundcloud.com/{username}",
    "https://www.patreon.com/{username}",
    "https://cash.app/${username}",
    "https://www.producthunt.com/@{username}",
    "https://hackernews.com/user?id={username}",
    "https://gitlab.com/{username}",
    "https://bitbucket.org/{username}",
    "https://stackoverflow.com/users/{username}",
    "https://www.quora.com/profile/{username}",
    "https://t.me/{username}",
    "https://www.snapchat.com/add/{username}",
    "https://open.spotify.com/user/{username}",
    "https://www.chess.com/member/{username}",
    "https://replit.com/@{username}",
    "https://codepen.io/{username}",
]

# ──────────────────────────────────────────────
# GOOGLE DORK TEMPLATES
# ──────────────────────────────────────────────
DORK_TEMPLATES = {
    "email_exposure":       'site:{target} "@{query}"',
    "login_pages":          'site:{target} inurl:login OR inurl:admin OR inurl:signin',
    "exposed_files":        'site:{target} ext:pdf OR ext:doc OR ext:xls OR ext:csv',
    "config_files":         'site:{target} ext:env OR ext:config OR ext:cfg OR ext:ini',
    "directory_listing":    'site:{target} intitle:"index of"',
    "passwords":            'site:{target} intext:password OR intext:passwd filetype:txt',
    "credentials":          'site:{target} "username" "password" filetype:log',
    "backup_files":         'site:{target} ext:bak OR ext:backup OR ext:old OR ext:orig',
    "database_dumps":       'site:{target} ext:sql OR ext:db OR ext:sqlite',
    "api_keys":             'site:{target} intext:"api_key" OR intext:"api_secret" OR intext:"access_token"',
    "ssh_keys":             'site:{target} "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"',
    "social_profiles":      'site:linkedin.com OR site:twitter.com OR site:instagram.com "{query}"',
    "phone_numbers":        'intext:"{query}" site:{target} "phone" OR "mobile" OR "tel"',
    "cached_pages":         'cache:{target}',
    "subdomains":           'site:*.{target}',
}

# ── v3.0 new module API keys ────────────────────
HYBRID_ANALYSIS_KEY     = os.getenv("HYBRID_ANALYSIS_KEY", "")   # malware_analysis
ANYRUN_KEY              = os.getenv("ANYRUN_KEY", "")            # malware_analysis
WIGLE_KEY               = os.getenv("WIGLE_KEY", "")            # wireless_intel
CENSYS_API_ID           = os.getenv("CENSYS_API_ID", "")        # cert_transparency
CENSYS_API_SECRET       = os.getenv("CENSYS_API_SECRET", "")    # cert_transparency
MARINETRAFFIC_KEY       = os.getenv("MARINETRAFFIC_KEY", "")    # physical_intel
SLACK_WEBHOOK           = os.getenv("SLACK_WEBHOOK", "")        # workflow alerts
DISCORD_WEBHOOK         = os.getenv("DISCORD_WEBHOOK", "")      # workflow alerts
