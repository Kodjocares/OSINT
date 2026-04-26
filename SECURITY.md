# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Active  |
| 1.x     | ⚠️ Critical fixes only |
| < 1.0   | ❌ No support |

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub Issues.**

If you discover a vulnerability in OSINT Tool itself (not in a third-party service it queries), please report it privately:

1. Go to **[Security → Advisories → New Draft Advisory](https://github.com/YOUR_USERNAME/osint-tool/security/advisories/new)** on GitHub
2. Describe the vulnerability, steps to reproduce, and potential impact
3. We will respond within **72 hours** with an assessment

### What counts as a vulnerability in this tool

- Code execution via crafted input (e.g. malicious file metadata, crafted API response)
- Credential or API key leakage in logs or error output
- Tor/proxy bypass that silently reveals real IP
- Dependency with a known CVE (if not already addressed)

### What does not count

- Findings from running the tool against external services (those belong to the respective service's security team)
- Rate limiting or access control on third-party APIs
- Theoretical risks with no practical exploit path

## Responsible Use

This tool is designed for **authorized security research only**.

If you discover that someone is using this tool to harm individuals or conduct unauthorized investigations, please report it to the appropriate authorities. Misuse of this tool violates the LICENSE and the Code of Conduct.
