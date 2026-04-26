"""
modules/workflow.py — OSINT automation, playbooks, bulk processing
Run predefined investigation checklists, process CSV targets, webhook alerts
"""

import os
import csv
import json
import logging
import threading
from typing import Dict, List, Callable, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Built-in investigation playbooks ───────────────────────────
PLAYBOOKS = {
    "email_full": {
        "name":        "Full Email Investigation",
        "description": "Complete profile for an email address",
        "steps": [
            {"module":"breach_check",   "method":"check_email",      "arg":"target"},
            {"module":"username_lookup","method":"investigate_email", "arg":"target"},
            {"module":"paste_monitor",  "method":"search_all",        "arg":"target"},
            {"module":"threat_intel",   "method":"domain_reputation", "arg":"target_domain"},
        ],
    },
    "domain_full": {
        "name":        "Full Domain Investigation",
        "description": "Complete technical + threat profile for a domain",
        "steps": [
            {"module":"domain_intel",      "method":"whois_lookup",         "arg":"target"},
            {"module":"domain_intel",      "method":"dns_lookup",           "arg":"target"},
            {"module":"domain_intel",      "method":"enumerate_subdomains", "arg":"target"},
            {"module":"domain_intel",      "method":"ssl_certificate_info", "arg":"target"},
            {"module":"cert_transparency", "method":"crtsh_search",         "arg":"target"},
            {"module":"dns_history",       "method":"full_history",         "arg":"target"},
            {"module":"threat_intel",      "method":"domain_reputation",    "arg":"target"},
            {"module":"cloud_discovery",   "method":"full_cloud_scan",      "arg":"target"},
            {"module":"web_archive",       "method":"domain_timeline",      "arg":"target"},
        ],
    },
    "person_full": {
        "name":        "Full Person Investigation",
        "description": "Username, social, breach, career, and paste profile",
        "steps": [
            {"module":"username_lookup","method":"search_username",  "arg":"target"},
            {"module":"social_media",  "method":"full_social_scan",  "arg":"target"},
            {"module":"github_recon",  "method":"user_recon",        "arg":"target"},
            {"module":"paste_monitor", "method":"search_all",        "arg":"target"},
            {"module":"career_intel",  "method":"patent_search",     "arg":"target"},
        ],
    },
    "ip_full": {
        "name":        "Full IP Investigation",
        "description": "Geolocation, threat intel, network, and classification",
        "steps": [
            {"module":"geolocation",  "method":"ip_geolocation",  "arg":"target"},
            {"module":"threat_intel", "method":"ip_reputation",   "arg":"target"},
            {"module":"ip_classifier","method":"classify",        "arg":"target"},
            {"module":"network_intel","method":"ip_to_asn",       "arg":"target"},
            {"module":"network_intel","method":"rdap_lookup",     "arg":"target"},
        ],
    },
    "company_full": {
        "name":        "Full Company Investigation",
        "description": "Registrations, financials, leaks, jobs, and web presence",
        "steps": [
            {"module":"company_intel",   "method":"search_company",     "arg":"target"},
            {"module":"financial_intel", "method":"ofac_check",         "arg":"target"},
            {"module":"financial_intel", "method":"icij_offshore_search","arg":"target"},
            {"module":"financial_intel", "method":"beneficial_ownership","arg":"target"},
            {"module":"career_intel",    "method":"scrape_job_postings", "arg":"target"},
            {"module":"paste_monitor",   "method":"search_all",         "arg":"target"},
            {"module":"darkweb_intel",   "method":"ransomware_leak_search","arg":"target"},
        ],
    },
    "threat_hunt": {
        "name":        "Threat Hunting",
        "description": "IOC analysis + malware + paste + dark web",
        "steps": [
            {"module":"threat_intel",    "method":"ip_reputation",      "arg":"target"},
            {"module":"threat_intel",    "method":"search_otx_pulses",   "arg":"target"},
            {"module":"ip_classifier",   "method":"classify",            "arg":"target"},
            {"module":"paste_monitor",   "method":"search_all",          "arg":"target"},
            {"module":"darkweb_intel",   "method":"ahmia_search",        "arg":"target"},
        ],
    },
}


class Workflow:
    """Run investigation playbooks, process bulk targets, send webhook alerts."""

    def __init__(self, modules_dict: Dict = None):
        self.modules  = modules_dict or {}
        self.results  = {}

    # ──────────────────────────────────────────────────────────
    # PLAYBOOK RUNNER
    # ──────────────────────────────────────────────────────────
    def run_playbook(self, playbook_id: str, target: str,
                     output_dir: str = "output",
                     on_step: Callable = None) -> Dict:
        """
        Execute a predefined investigation playbook for a target.

        Args:
            playbook_id: Key from PLAYBOOKS dict
            target:      Investigation target (domain/email/IP/username)
            output_dir:  Where to save results
            on_step:     Optional callback(step_name, result) called after each step
        """
        if playbook_id not in PLAYBOOKS:
            return {"error": f"Unknown playbook: {playbook_id}",
                    "available": list(PLAYBOOKS.keys())}

        playbook = PLAYBOOKS[playbook_id]
        run_id   = datetime.now().strftime("%Y%m%d_%H%M%S")
        result   = {
            "playbook":   playbook_id,
            "playbook_name": playbook["name"],
            "target":     target,
            "run_id":     run_id,
            "started":    datetime.now().isoformat(),
            "steps":      {},
            "completed":  0,
            "errors":     0,
        }

        for step in playbook["steps"]:
            module_name = step["module"]
            method_name = step["method"]
            step_key    = f"{module_name}.{method_name}"

            logger.info(f"[PLAYBOOK] {playbook_id} → {step_key}")

            # Determine argument
            if step.get("arg") == "target_domain" and "@" in target:
                arg = target.split("@")[1]
            else:
                arg = target

            # Run step
            try:
                module = self.modules.get(module_name)
                if not module:
                    result["steps"][step_key] = {"error": f"Module '{module_name}' not loaded"}
                    result["errors"] += 1
                    continue

                method = getattr(module, method_name, None)
                if not method:
                    result["steps"][step_key] = {"error": f"Method '{method_name}' not found"}
                    result["errors"] += 1
                    continue

                step_result = method(arg)
                result["steps"][step_key] = step_result
                result["completed"] += 1

                if on_step:
                    on_step(step_key, step_result)

            except Exception as e:
                logger.error(f"[PLAYBOOK] {step_key} failed: {e}")
                result["steps"][step_key] = {"error": str(e)}
                result["errors"] += 1

        result["finished"]  = datetime.now().isoformat()
        result["total_steps"] = len(playbook["steps"])

        # Save result
        os.makedirs(output_dir, exist_ok=True)
        safe_target = "".join(c for c in target if c.isalnum() or c in "-_.")[:30]
        out_path    = os.path.join(output_dir, f"playbook_{playbook_id}_{safe_target}_{run_id}.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        result["output_file"] = out_path

        return result

    # ──────────────────────────────────────────────────────────
    # BULK TARGET PROCESSING
    # ──────────────────────────────────────────────────────────
    def process_csv(self, csv_path: str, playbook_id: str,
                    target_column: str = "target",
                    output_dir: str = "output",
                    max_workers: int = 3) -> Dict:
        """
        Read a CSV of targets and run a playbook on each.
        CSV must have a column matching target_column (default: 'target').
        """
        if not os.path.exists(csv_path):
            return {"error": f"CSV file not found: {csv_path}"}

        targets = []
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if target_column not in (reader.fieldnames or []):
                return {"error": f"Column '{target_column}' not found in CSV",
                        "columns": reader.fieldnames}
            for row in reader:
                t = row.get(target_column,"").strip()
                if t:
                    targets.append(t)

        results_map: Dict[str, Any] = {}
        lock = threading.Lock()

        def run_one(t: str):
            res = self.run_playbook(playbook_id, t, output_dir=output_dir)
            with lock:
                results_map[t] = {
                    "completed": res.get("completed",0),
                    "errors":    res.get("errors",0),
                    "output":    res.get("output_file"),
                }

        # Thread pool
        threads = []
        for target in targets:
            while len([t for t in threads if t.is_alive()]) >= max_workers:
                import time; time.sleep(0.5)
            t = threading.Thread(target=run_one, args=(target,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return {
            "csv_path":     csv_path,
            "playbook":     playbook_id,
            "total_targets":len(targets),
            "processed":    len(results_map),
            "results":      results_map,
        }

    # ──────────────────────────────────────────────────────────
    # WEBHOOK ALERTS
    # ──────────────────────────────────────────────────────────
    def send_webhook(self, webhook_url: str, data: Dict,
                     platform: str = "auto") -> Dict:
        """
        Send results to Slack, Discord, Teams, or generic webhook.
        """
        import requests

        # Auto-detect platform
        if platform == "auto":
            if "slack.com/services" in webhook_url:
                platform = "slack"
            elif "discord.com/api/webhooks" in webhook_url:
                platform = "discord"
            elif "webhook.office.com" in webhook_url:
                platform = "teams"
            else:
                platform = "generic"

        # Format payload
        title   = f"OSINT Alert — {data.get('target','unknown')}"
        summary = (f"Playbook: {data.get('playbook_name','N/A')} | "
                   f"Steps: {data.get('completed',0)}/{data.get('total_steps',0)} | "
                   f"Errors: {data.get('errors',0)}")

        if platform == "slack":
            payload = {
                "text": f"*{title}*\n{summary}",
                "attachments": [{
                    "color":  "#00e5ff",
                    "fields": [
                        {"title": "Target",   "value": data.get("target",""), "short": True},
                        {"title": "Playbook", "value": data.get("playbook",""), "short": True},
                        {"title": "Started",  "value": data.get("started",""), "short": True},
                        {"title": "Finished", "value": data.get("finished",""), "short": True},
                    ]
                }]
            }
        elif platform == "discord":
            payload = {
                "username": "OSINT Tool",
                "embeds": [{
                    "title":       title,
                    "description": summary,
                    "color":       0x00e5ff,
                    "fields": [
                        {"name":"Target",   "value":data.get("target",""), "inline":True},
                        {"name":"Playbook", "value":data.get("playbook",""), "inline":True},
                    ]
                }]
            }
        elif platform == "teams":
            payload = {
                "@type":      "MessageCard",
                "@context":   "http://schema.org/extensions",
                "themeColor": "00e5ff",
                "summary":    title,
                "sections":   [{"activityTitle": title, "activityText": summary}]
            }
        else:
            payload = {"title": title, "summary": summary, "data": data}

        try:
            resp = requests.post(webhook_url, json=payload, timeout=10)
            return {"sent": True, "platform": platform,
                    "status_code": resp.status_code}
        except Exception as e:
            return {"sent": False, "error": str(e)}

    # ──────────────────────────────────────────────────────────
    # PLAYBOOK INFO
    # ──────────────────────────────────────────────────────────
    def list_playbooks(self) -> Dict:
        return {
            "playbooks": [
                {
                    "id":          pid,
                    "name":        pb["name"],
                    "description": pb["description"],
                    "step_count":  len(pb["steps"]),
                    "modules":     list(set(s["module"] for s in pb["steps"])),
                }
                for pid, pb in PLAYBOOKS.items()
            ]
        }
