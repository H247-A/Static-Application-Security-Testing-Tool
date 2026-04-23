#!/usr/bin/env python3
"""
sast.py — Static Application Security Testing (SAST) Tool
CMPE 279 Software Security Technologies — SJSU Spring 2026

Usage:
  python sast.py scan <file_or_dir>
  python sast.py scan <file_or_dir> --json out.json
  python sast.py scan <file_or_dir> --html out.html
  python sast.py scan <file_or_dir> --severity HIGH
"""

import argparse
import os
import sys
from typing import List, Tuple

from analyzer import analyze_source
from rules import Finding, SEVERITY_RANK
from report import print_terminal, export_json, export_html


def collect_files(path: str) -> List[str]:
    """Return list of .py files under path (file or directory)."""
    if os.path.isfile(path):
        return [path] if path.endswith(".py") else []
    files = []
    for root, _, names in os.walk(path):
        # skip common noise dirs
        if any(skip in root for skip in ["__pycache__", ".git", ".venv", "node_modules"]):
            continue
        for name in names:
            if name.endswith(".py"):
                files.append(os.path.join(root, name))
    return sorted(files)


def scan_all(files: List[str]) -> Tuple[List[Finding], int]:
    all_findings = []
    total_lines = 0
    for filepath in files:
        try:
            source = open(filepath, encoding="utf-8", errors="ignore").read()
            total_lines += source.count("\n") + 1
            findings = analyze_source(source, filepath)
            all_findings.extend(findings)
        except Exception as e:
            print(f"  [!] Could not read {filepath}: {e}")
    return all_findings, total_lines


def filter_severity(findings: List[Finding], min_severity: str) -> List[Finding]:
    threshold = SEVERITY_RANK.get(min_severity, 99)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 99) <= threshold]


# ── subcommand: scan ───────────────────────────────────────────────────────────

def cmd_scan(args):
    files = collect_files(args.path)
    if not files:
        print(f"[!] No Python files found at: {args.path}")
        sys.exit(2)

    print(f"\n[*] Scanning {len(files)} file(s)...")
    findings, lines = scan_all(files)

    if args.severity:
        findings = filter_severity(findings, args.severity)

    print_terminal(findings, files_scanned=len(files), lines_scanned=lines)

    if args.json:
        export_json(findings, files_scanned=len(files), outfile=args.json)

    if args.html:
        export_html(findings, files_scanned=len(files),
                    lines_scanned=lines, outfile=args.html)

    # CI/CD exit code — exit 1 if HIGH or CRITICAL found
    worst = min(
        (SEVERITY_RANK.get(f.severity, 99) for f in findings),
        default=99
    )
    if worst <= SEVERITY_RANK.get(args.fail_on, 1):
        sys.exit(1)


# ── subcommand: list-rules ─────────────────────────────────────────────────────

def cmd_list_rules(_args):
    from rules import RULES_META
    print(f"\n{'ID':<6}  {'CWE':<10}  {'Severity':<10}  Description")
    print("─" * 65)
    for rid, cwe, sev, desc in RULES_META:
        print(f"{rid:<6}  {cwe:<10}  {sev:<10}  {desc}")
    print(f"\n  Total: {len(RULES_META)} rules\n")


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="sast",
        description="SAST Security Scanner — CMPE 279, SJSU"
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a file or directory")
    p_scan.add_argument("path", help="Python file or project directory")
    p_scan.add_argument("--json", metavar="FILE", help="Write JSON report")
    p_scan.add_argument("--html", metavar="FILE", help="Write HTML report")
    p_scan.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Only show findings at this severity or above"
    )
    p_scan.add_argument(
        "--fail-on",
        dest="fail_on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Exit code 1 if findings at this severity or above (default: HIGH)"
    )

    # list-rules
    sub.add_parser("list-rules", help="List all detection rules")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "list-rules":
        cmd_list_rules(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
