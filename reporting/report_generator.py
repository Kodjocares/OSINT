"""
reporting/report_generator.py — HTML/PDF/JSON report generation with charts
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate professional OSINT reports in HTML, PDF, and JSON formats."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ─────────────────────────────────────────────
    # JSON REPORT
    # ─────────────────────────────────────────────
    def save_json(self, data: Dict, filename: str = "report.json") -> str:
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"[REPORT] JSON saved: {filepath}")
        return filepath

    # ─────────────────────────────────────────────
    # HTML REPORT
    # ─────────────────────────────────────────────
    def generate_html_report(self, data: Dict, title: str = "OSINT Report",
                             filename: str = "report.html") -> str:
        filepath = os.path.join(self.output_dir, filename)
        html = self._build_html(data, title)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"[REPORT] HTML saved: {filepath}")
        return filepath

    def _build_html(self, data: Dict, title: str) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def _render_value(v: Any, depth: int = 0) -> str:
            if isinstance(v, dict):
                rows = "".join(
                    f"<tr><td class='key'>{k}</td><td>{_render_value(val, depth+1)}</td></tr>"
                    for k, val in v.items()
                )
                return f"<table class='nested'>{rows}</table>"
            elif isinstance(v, list):
                if not v:
                    return "<span class='empty'>—</span>"
                items = "".join(f"<li>{_render_value(i, depth+1)}</li>" for i in v)
                return f"<ul>{items}</ul>"
            elif v is None:
                return "<span class='null'>null</span>"
            else:
                sv = str(v)
                if sv.startswith("http"):
                    return f"<a href='{sv}' target='_blank'>{sv}</a>"
                return f"<span>{sv}</span>"

        sections_html = ""
        for section_key, section_data in data.items():
            section_title = section_key.replace("_", " ").title()
            content = _render_value(section_data)
            sections_html += f"""
            <section class="card">
                <h2>{section_title}</h2>
                <div class="card-content">{content}</div>
            </section>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #00d4ff; --accent2: #ff6b35; --text: #c9d1d9;
    --text-dim: #8b949e; --green: #3fb950; --red: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.6; }}
  header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }}
  header h1 {{ color: var(--accent); font-size: 22px; letter-spacing: 2px; }}
  header .meta {{ color: var(--text-dim); font-size: 11px; text-align: right; }}
  .logo {{ color: var(--accent2); font-size: 28px; font-weight: bold; margin-right: 16px; }}
  main {{ max-width: 1200px; margin: 30px auto; padding: 0 20px; }}
  .summary-bar {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat-badge {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 20px; flex: 1; min-width: 120px; text-align: center; }}
  .stat-badge .num {{ font-size: 24px; color: var(--accent); font-weight: bold; }}
  .stat-badge .lbl {{ font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
  .card h2 {{ background: rgba(0,212,255,0.08); border-bottom: 1px solid var(--border); padding: 12px 20px; font-size: 13px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--accent); }}
  .card-content {{ padding: 16px 20px; overflow-x: auto; }}
  table.nested {{ width: 100%; border-collapse: collapse; }}
  table.nested tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
  table.nested td {{ padding: 5px 10px; vertical-align: top; border-bottom: 1px solid rgba(48,54,61,0.5); }}
  td.key {{ color: var(--text-dim); font-size: 11px; min-width: 140px; white-space: nowrap; text-transform: uppercase; letter-spacing: 0.5px; }}
  ul {{ list-style: none; padding-left: 8px; }}
  ul li::before {{ content: "▸ "; color: var(--accent2); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .null {{ color: var(--text-dim); }}
  .empty {{ color: var(--text-dim); }}
  footer {{ text-align: center; padding: 30px; color: var(--text-dim); font-size: 11px; border-top: 1px solid var(--border); margin-top: 40px; }}
  .warning {{ background: rgba(248,81,73,0.1); border: 1px solid var(--red); border-radius: 6px; padding: 10px 16px; margin-bottom: 20px; color: var(--red); font-size: 12px; }}
</style>
</head>
<body>
<header>
  <div style="display:flex;align-items:center">
    <span class="logo">⬡</span>
    <h1>{title}</h1>
  </div>
  <div class="meta">
    <div>Generated: {timestamp}</div>
    <div>OSINT Research Tool v1.0</div>
  </div>
</header>
<main>
  <div class="warning">⚠ This report contains sensitive intelligence data. Handle with care and in accordance with applicable laws.</div>
  {sections_html}
</main>
<footer>OSINT Tool — For authorized research and security purposes only</footer>
</body>
</html>"""

    # ─────────────────────────────────────────────
    # VISUALIZATION CHARTS
    # ─────────────────────────────────────────────
    def generate_breach_chart(self, breach_data: List[Dict], filename: str = "breach_chart.png") -> str:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches

            if not breach_data:
                return ""

            names   = [b.get("name", "Unknown")[:20] for b in breach_data[:15]]
            counts  = [b.get("pwn_count", 0) for b in breach_data[:15]]

            fig, ax = plt.subplots(figsize=(12, 6))
            fig.patch.set_facecolor("#0d1117")
            ax.set_facecolor("#161b22")

            bars = ax.barh(names, counts, color="#00d4ff", alpha=0.8, edgecolor="#30363d")
            ax.set_xlabel("Affected Accounts", color="#8b949e")
            ax.set_title("Data Breaches — Account Exposure", color="#c9d1d9", fontsize=14, pad=15)
            ax.tick_params(colors="#8b949e")
            for spine in ax.spines.values():
                spine.set_edgecolor("#30363d")
            ax.xaxis.label.set_color("#8b949e")

            plt.tight_layout()
            filepath = os.path.join(self.output_dir, filename)
            plt.savefig(filepath, dpi=150, bbox_inches="tight", facecolor="#0d1117")
            plt.close()
            return filepath
        except ImportError:
            logger.warning("matplotlib not installed")
            return ""

    def generate_platform_presence_chart(self, platform_results: List[Dict],
                                          filename: str = "platform_chart.png") -> str:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            found     = [r for r in platform_results if r.get("status") == 200]
            not_found = [r for r in platform_results if r.get("status") == 404]
            errors    = [r for r in platform_results if "error" in str(r.get("status", ""))]

            labels = ["Found", "Not Found", "Errors"]
            sizes  = [len(found), len(not_found), len(errors)]
            colors = ["#3fb950", "#f85149", "#e3b341"]

            fig, ax = plt.subplots(figsize=(7, 7))
            fig.patch.set_facecolor("#0d1117")
            ax.set_facecolor("#0d1117")

            wedges, texts, autotexts = ax.pie(
                sizes, labels=labels, colors=colors, autopct="%1.1f%%",
                startangle=90, textprops={"color": "#c9d1d9"},
            )
            ax.set_title("Username Platform Presence", color="#c9d1d9", fontsize=13, pad=15)

            filepath = os.path.join(self.output_dir, filename)
            plt.savefig(filepath, dpi=150, bbox_inches="tight", facecolor="#0d1117")
            plt.close()
            return filepath
        except ImportError:
            return ""

    # ─────────────────────────────────────────────
    # FULL REPORT
    # ─────────────────────────────────────────────
    def full_report(self, all_data: Dict, target: str,
                    formats: List[str] = None) -> Dict:
        """Generate reports in all requested formats."""
        formats = formats or ["html", "json"]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c for c in target if c.isalnum() or c in "-_.")

        outputs = {}
        if "json" in formats:
            outputs["json"] = self.save_json(all_data, f"{safe_target}_{ts}.json")
        if "html" in formats:
            outputs["html"] = self.generate_html_report(
                all_data,
                title=f"OSINT Report — {target}",
                filename=f"{safe_target}_{ts}.html"
            )
        return outputs
