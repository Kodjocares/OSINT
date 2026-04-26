"""
modules/monitoring.py — Continuous monitoring with alerts for target changes
"""

import json
import os
import time
import logging
import hashlib
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Callable, Optional
from config import (
    OUTPUT_DIR, ALERT_EMAIL, SMTP_HOST, SMTP_PORT,
    SMTP_USER, SMTP_PASS, MONITOR_INTERVAL_HOURS
)

logger = logging.getLogger(__name__)

MONITOR_STATE_FILE = os.path.join(OUTPUT_DIR, "monitor_state.json")

class Monitor:
    """Schedule periodic OSINT scans and alert on changes."""

    def __init__(self):
        self.state = self._load_state()
        self.tasks: List[Dict] = []

    # ─────────────────────────────────────────────
    # STATE MANAGEMENT
    # ─────────────────────────────────────────────
    def _load_state(self) -> Dict:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        if os.path.exists(MONITOR_STATE_FILE):
            try:
                with open(MONITOR_STATE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"targets": {}, "history": []}

    def _save_state(self):
        with open(MONITOR_STATE_FILE, "w") as f:
            json.dump(self.state, f, indent=2, default=str)

    def _hash_data(self, data: dict) -> str:
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    # ─────────────────────────────────────────────
    # TARGET REGISTRATION
    # ─────────────────────────────────────────────
    def register_target(self, target_id: str, target_type: str,
                        target_value: str, description: str = "") -> Dict:
        """Register a new target for monitoring."""
        self.state["targets"][target_id] = {
            "id":           target_id,
            "type":         target_type,   # domain | ip | email | username
            "value":        target_value,
            "description":  description,
            "registered_at":datetime.now().isoformat(),
            "last_checked": None,
            "last_hash":    None,
            "alert_count":  0,
            "active":       True,
        }
        self._save_state()
        return self.state["targets"][target_id]

    def list_targets(self) -> List[Dict]:
        return list(self.state["targets"].values())

    def remove_target(self, target_id: str) -> bool:
        if target_id in self.state["targets"]:
            del self.state["targets"][target_id]
            self._save_state()
            return True
        return False

    # ─────────────────────────────────────────────
    # CHANGE DETECTION
    # ─────────────────────────────────────────────
    def check_target(self, target_id: str, scan_function: Callable,
                     **scan_kwargs) -> Dict:
        """Run a scan and compare to previous state, alert if changed."""
        if target_id not in self.state["targets"]:
            return {"error": f"Target '{target_id}' not registered"}

        target = self.state["targets"][target_id]
        scan_result = scan_function(**scan_kwargs)
        new_hash = self._hash_data(scan_result)
        old_hash = target.get("last_hash")

        changed = old_hash is not None and new_hash != old_hash
        now = datetime.now().isoformat()

        # Update state
        target["last_checked"] = now
        target["last_hash"]    = new_hash

        check_record = {
            "target_id":  target_id,
            "checked_at": now,
            "changed":    changed,
            "hash":       new_hash,
            "result":     scan_result,
        }

        # Append to history
        if "history" not in self.state:
            self.state["history"] = []
        self.state["history"].append({
            "target_id":  target_id,
            "checked_at": now,
            "changed":    changed,
            "hash":       new_hash,
        })
        # Keep only last 100 history entries
        self.state["history"] = self.state["history"][-100:]

        if changed:
            target["alert_count"] += 1
            logger.warning(f"[MONITOR] Change detected for target: {target_id}")
            self._send_alert(target, scan_result)

        self._save_state()
        return check_record

    # ─────────────────────────────────────────────
    # ALERTING
    # ─────────────────────────────────────────────
    def _send_alert(self, target: Dict, new_data: Dict):
        """Send an email alert when a change is detected."""
        if not ALERT_EMAIL or not SMTP_USER or not SMTP_PASS:
            logger.info(f"[MONITOR] Alert triggered for {target['id']} but email not configured.")
            self._log_alert(target, new_data)
            return

        try:
            subject = f"[OSINT Monitor] Change detected: {target['value']}"
            body = f"""
OSINT Monitor Alert
===================
Target ID:    {target['id']}
Target Type:  {target['type']}
Target Value: {target['value']}
Detected At:  {datetime.now().isoformat()}
Alert Count:  {target['alert_count']}

Change Summary:
A change was detected in the monitored data for this target.
Full scan data has been logged.

Description:  {target.get('description', 'N/A')}
"""
            msg = MIMEMultipart()
            msg["From"]    = SMTP_USER
            msg["To"]      = ALERT_EMAIL
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            logger.info(f"[MONITOR] Alert email sent to {ALERT_EMAIL}")
        except Exception as e:
            logger.error(f"[MONITOR] Failed to send alert email: {e}")

    def _log_alert(self, target: Dict, new_data: Dict):
        """Log alert to file when email is not configured."""
        alerts_dir = os.path.join(OUTPUT_DIR, "alerts")
        os.makedirs(alerts_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        alert_file = os.path.join(alerts_dir, f"alert_{target['id']}_{ts}.json")
        with open(alert_file, "w") as f:
            json.dump({
                "target":   target,
                "new_data": new_data,
                "alert_at": ts,
            }, f, indent=2, default=str)
        logger.info(f"[MONITOR] Alert logged to {alert_file}")

    # ─────────────────────────────────────────────
    # SCHEDULED MONITORING
    # ─────────────────────────────────────────────
    def start_scheduler(self, target_id: str, scan_function: Callable,
                        interval_hours: int = None, **scan_kwargs):
        """
        Start a monitoring loop for a target.
        Runs scan every interval_hours. Blocking — run in a separate thread.
        """
        interval = (interval_hours or MONITOR_INTERVAL_HOURS) * 3600
        logger.info(f"[MONITOR] Starting scheduler for {target_id}, every {interval/3600:.1f}h")
        while True:
            try:
                result = self.check_target(target_id, scan_function, **scan_kwargs)
                logger.info(f"[MONITOR] Scan complete for {target_id} — changed: {result.get('changed')}")
            except Exception as e:
                logger.error(f"[MONITOR] Scheduler error for {target_id}: {e}")
            time.sleep(interval)

    def get_history(self, target_id: str = None) -> List[Dict]:
        history = self.state.get("history", [])
        if target_id:
            history = [h for h in history if h["target_id"] == target_id]
        return history
