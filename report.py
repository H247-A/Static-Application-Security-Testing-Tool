"""
report.py — Output formatters: terminal, JSON, HTML
"""

import json
from datetime import datetime
from typing import List
from rules import Finding, SEVERITY_RANK

# ── terminal colors ────────────────────────────────────────────────────────────
C = {
    "CRITICAL": "\033[95m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
    "INFO":     "\033[96m",
    "GREEN":    "\033[92m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "R":        "\033[0m",
}


def _sev_color(sev: str) -> str:
    return C.get(sev, "")


def print_terminal(findings: List[Finding], files_scanned: int, lines_scanned: int):
    B, R, DIM = C["BOLD"], C["R"], C["DIM"]

    print(f"\n{B}{'─'*65}{R}")
    print(f"{B}  SAST SECURITY REPORT{R}")
    print(f"{DIM}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
          f"{files_scanned} file(s)  |  {lines_scanned} lines{R}")
    print(f"{B}{'─'*65}{R}")

    if not findings:
        print(f"\n  {C['GREEN']}✓  No vulnerabilities detected.{R}\n")
        return

    # severity counts
    counts = {s: 0 for s in SEVERITY_RANK}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n  {B}SUMMARY{R}")
    for sev in SEVERITY_RANK:
        if counts.get(sev):
            print(f"  {_sev_color(sev)}{sev:<10}{R}  {counts[sev]} finding(s)")

    print(f"\n  {B}FINDINGS{R}")
    print(f"{'─'*65}")

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 99))

    for f in sorted_findings:
        sc = _sev_color(f.severity)
        print(f"\n{sc}{B}[{f.severity}] {f.rule_id} — {f.title}{R}")
        print(f"  {DIM}{f.filename}:{f.line}:{f.col}{R}    {DIM}{f.cwe}{R}")
        print(f"  Issue : {f.detail}")
        print(f"  Fix   : {f.fix}")

    print(f"\n{'─'*65}")
    total = len(findings)
    crit  = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    print(f"{B}  {total} issue(s) found.  {crit} require immediate attention.{R}\n")


def export_json(findings: List[Finding], files_scanned: int, outfile: str):
    data = {
        "tool": "SAST Scanner — CMPE 279",
        "generated": datetime.now().isoformat(),
        "summary": {
            "files_scanned": files_scanned,
            "total_findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f.severity == sev)
                for sev in SEVERITY_RANK
            }
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "cwe": f.cwe,
                "severity": f.severity,
                "file": f.filename,
                "line": f.line,
                "col": f.col,
                "title": f.title,
                "detail": f.detail,
                "fix": f.fix,
            }
            for f in sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 99))
        ]
    }
    with open(outfile, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"  [*] JSON report saved → {outfile}")


def export_html(findings: List[Finding], files_scanned: int, lines_scanned: int, outfile: str):
    SEV_STYLE = {
        "CRITICAL": "background:#6d28d9;color:#fff",
        "HIGH":     "background:#dc2626;color:#fff",
        "MEDIUM":   "background:#d97706;color:#fff",
        "LOW":      "background:#2563eb;color:#fff",
        "INFO":     "background:#0891b2;color:#fff",
    }

    def badge(sev):
        style = SEV_STYLE.get(sev, "background:#6b7280;color:#fff")
        return f'<span style="font-size:11px;font-weight:700;padding:2px 9px;border-radius:4px;{style}">{sev}</span>'

    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_RANK}

    rows = ""
    for f in sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 99)):
        rows += f"""
        <tr>
          <td>{badge(f.severity)}</td>
          <td style="font-family:monospace;font-weight:600">{f.rule_id}</td>
          <td><a href="https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html"
                 target="_blank" style="color:#2563eb;text-decoration:none">{f.cwe}</a></td>
          <td style="font-weight:600">{f.title}</td>
          <td style="font-family:monospace;color:#555;font-size:12px">{f.filename}:{f.line}</td>
          <td style="font-size:13px;color:#444">{f.detail}</td>
          <td style="font-size:13px;color:#15803d">{f.fix}</td>
        </tr>"""

    stat_cards = ""
    for label, val, color in [
        ("Files Scanned", files_scanned, "#1d4ed8"),
        ("Lines Analyzed", lines_scanned, "#0f766e"),
        ("Total Findings", len(findings), "#b91c1c"),
        ("Critical", counts.get("CRITICAL", 0), "#7c3aed"),
        ("High", counts.get("HIGH", 0), "#dc2626"),
        ("Medium", counts.get("MEDIUM", 0), "#d97706"),
    ]:
        stat_cards += f"""
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center">
          <div style="font-size:26px;font-weight:700;color:{color}">{val}</div>
          <div style="font-size:12px;color:#6b7280;margin-top:2px">{label}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAST Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0 }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f8fafc; color: #111; padding: 32px }}
  h1 {{ font-size: 22px; font-weight: 700 }}
  .meta {{ color: #6b7280; font-size: 13px; margin: 4px 0 24px }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
           gap: 12px; margin-bottom: 28px }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border: 1px solid #e5e7eb; border-radius: 10px; overflow: hidden;
           font-size: 13px }}
  th {{ background: #f9fafb; padding: 10px 14px; text-align: left;
        font-size: 12px; color: #6b7280; font-weight: 600; border-bottom: 1px solid #e5e7eb }}
  td {{ padding: 11px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: top }}
  tr:last-child td {{ border-bottom: none }}
  tr:hover td {{ background: #fafafa }}
</style>
</head>
<body>
  <h1>SAST Security Report</h1>
  <p class="meta">
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    CMPE 279 — Software Security Technologies, SJSU
  </p>

  <div class="grid">{stat_cards}</div>

  {"<p style='color:#16a34a;font-weight:600;margin-bottom:24px'>✓ No vulnerabilities detected.</p>" if not findings else ""}

  {f'''<table>
    <thead>
      <tr>
        <th>Severity</th><th>Rule</th><th>CWE</th><th>Title</th>
        <th>Location</th><th>Detail</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>''' if findings else ""}
</body>
</html>"""

    with open(outfile, "w") as fh:
        fh.write(html)
    print(f"  [*] HTML report saved → {outfile}")
