"""
modules/github_recon.py — GitHub secret mining, code search, commit history analysis
Find exposed API keys, credentials, internal hostnames, and sensitive data in public repos
"""

import re
import logging
from typing import Dict, List
from utils.helpers import safe_request

logger = logging.getLogger(__name__)

GH_API = "https://api.github.com"

# Patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key":        r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub Token":          r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth":          r"gho_[0-9a-zA-Z]{36}",
    "Slack Token":           r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "Slack Webhook":         r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+",
    "Google API Key":        r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":          r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Stripe Secret Key":     r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable":    r"pk_live_[0-9a-zA-Z]{24}",
    "Private RSA Key":       r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key":        r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Private Key":   r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Heroku API Key":        r"[hH]eroku.{0,20}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]",
    "Twilio API Key":        r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key":      r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    "Password in Code":      r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",
    "Generic Secret":        r"(?i)(secret|token|api_key|apikey|auth_token)\s*[=:]\s*['\"][a-zA-Z0-9\-_\.]{10,}['\"]",
    "Database URL":          r"(postgres|mysql|mongodb|redis)://[^\s\"']+",
    "IP Address (internal)": r"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}",
    "JWT Token":             r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
}


class GitHubRecon:
    """Mine GitHub for secrets, sensitive data, and intelligence about a target."""

    def __init__(self, github_token: str = ""):
        self.token = github_token
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"

    # ──────────────────────────────────────────────────────────
    # USER / ORG RECON
    # ──────────────────────────────────────────────────────────
    def user_recon(self, username: str) -> Dict:
        result = {"username": username, "profile": {}, "repos": [], "orgs": [], "emails": []}

        resp = safe_request(f"{GH_API}/users/{username}", headers=self.headers)
        if resp and resp.status_code == 200:
            d = resp.json()
            result["profile"] = {k: d.get(k) for k in [
                "name","bio","company","location","email","blog",
                "twitter_username","followers","following","public_repos",
                "public_gists","created_at","updated_at","avatar_url","hireable",
            ]}

        repos_resp = safe_request(f"{GH_API}/users/{username}/repos",
                                  params={"per_page": 100, "sort": "updated"},
                                  headers=self.headers)
        if repos_resp and repos_resp.status_code == 200:
            for r in repos_resp.json():
                result["repos"].append({
                    "name": r.get("name"), "full_name": r.get("full_name"),
                    "description": r.get("description"), "language": r.get("language"),
                    "stars": r.get("stargazers_count"), "forks": r.get("forks_count"),
                    "url": r.get("html_url"), "default_branch": r.get("default_branch"),
                    "updated_at": r.get("updated_at"), "size": r.get("size"),
                    "topics": r.get("topics", []),
                })

        orgs_resp = safe_request(f"{GH_API}/users/{username}/orgs", headers=self.headers)
        if orgs_resp and orgs_resp.status_code == 200:
            result["orgs"] = [o.get("login") for o in orgs_resp.json()]

        return result

    # ──────────────────────────────────────────────────────────
    # SEARCH CODE FOR SECRETS
    # ──────────────────────────────────────────────────────────
    def search_code_secrets(self, query: str, org: str = None) -> Dict:
        """Search GitHub code for secrets related to a query/org (requires token)."""
        if not self.token:
            return {"error": "GitHub token required for code search", "query": query}

        search_query = query
        if org:
            search_query = f"{query} org:{org}"

        resp = safe_request(
            f"{GH_API}/search/code",
            params={"q": search_query, "per_page": 20},
            headers=self.headers,
        )
        findings = []
        if resp and resp.status_code == 200:
            items = resp.json().get("items", [])
            for item in items:
                findings.append({
                    "repo":        item.get("repository", {}).get("full_name"),
                    "file":        item.get("name"),
                    "path":        item.get("path"),
                    "url":         item.get("html_url"),
                    "raw_url":     item.get("url"),
                    "repo_url":    item.get("repository", {}).get("html_url"),
                })
        return {"query": search_query, "count": len(findings), "findings": findings}

    # ──────────────────────────────────────────────────────────
    # SCAN REPO FOR SECRETS
    # ──────────────────────────────────────────────────────────
    def scan_repo_for_secrets(self, repo_full_name: str,
                               max_files: int = 50) -> Dict:
        """Scan a repo's files for hardcoded secrets using regex patterns."""
        result = {
            "repo":     repo_full_name,
            "findings": [],
            "files_scanned": 0,
            "secrets_found": 0,
        }

        # Get file tree
        tree_resp = safe_request(
            f"{GH_API}/repos/{repo_full_name}/git/trees/HEAD",
            params={"recursive": "1"},
            headers=self.headers,
        )
        if not tree_resp or tree_resp.status_code != 200:
            result["error"] = "Could not fetch repo tree"
            return result

        files = [
            item for item in tree_resp.json().get("tree", [])
            if item.get("type") == "blob" and item.get("size", 0) < 500_000
            and not any(item["path"].endswith(ext) for ext in
                        [".png",".jpg",".gif",".ico",".svg",".woff",".ttf",".zip",".pdf"])
        ][:max_files]

        for file_item in files:
            result["files_scanned"] += 1
            raw_url = (f"https://raw.githubusercontent.com/"
                       f"{repo_full_name}/HEAD/{file_item['path']}")
            file_resp = safe_request(raw_url)
            if not file_resp or file_resp.status_code != 200:
                continue

            content = file_resp.text
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    result["findings"].append({
                        "file":        file_item["path"],
                        "secret_type": secret_type,
                        "matches":     matches[:3],
                        "file_url":    f"https://github.com/{repo_full_name}/blob/HEAD/{file_item['path']}",
                    })
                    result["secrets_found"] += len(matches)

        return result

    # ──────────────────────────────────────────────────────────
    # COMMIT HISTORY ANALYSIS
    # ──────────────────────────────────────────────────────────
    def analyze_commits(self, repo_full_name: str, limit: int = 50) -> Dict:
        """Extract author emails, names, and patterns from commit history."""
        resp = safe_request(
            f"{GH_API}/repos/{repo_full_name}/commits",
            params={"per_page": limit},
            headers=self.headers,
        )
        if not resp or resp.status_code != 200:
            return {"error": "Could not fetch commits", "repo": repo_full_name}

        authors, emails, commits_data = set(), set(), []
        for c in resp.json():
            commit = c.get("commit", {})
            author = commit.get("author", {})
            gh_author = c.get("author") or {}
            name  = author.get("name", "")
            email = author.get("email", "")
            if name:  authors.add(name)
            if email: emails.add(email)
            commits_data.append({
                "sha":        c.get("sha", "")[:8],
                "message":    commit.get("message", "").split("\n")[0][:100],
                "author":     name,
                "email":      email,
                "date":       author.get("date"),
                "github_user":gh_author.get("login"),
            })

        return {
            "repo":         repo_full_name,
            "unique_authors": list(authors),
            "unique_emails":  list(emails),
            "commit_count":   len(commits_data),
            "commits":        commits_data,
        }

    # ──────────────────────────────────────────────────────────
    # DOMAIN / ORG CODE SEARCH
    # ──────────────────────────────────────────────────────────
    def search_domain_exposure(self, domain: str) -> Dict:
        """Search GitHub for any code mentioning a target domain."""
        queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" internal',
        ]
        all_findings = []
        for q in queries:
            res = self.search_code_secrets(q)
            all_findings.extend(res.get("findings", []))

        return {
            "domain":        domain,
            "total_findings":len(all_findings),
            "findings":      all_findings,
        }
