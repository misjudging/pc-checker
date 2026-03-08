#!/usr/bin/env python3
"""
FiveM PC checker (defensive scanner).

This tool is designed for forensic/administrative use on systems where you have
authorization to scan. It looks for indicator matches in:
 - running processes
 - installed/running services
 - selected registry startup keys
 - filesystem path patterns
 - boot configuration flags often abused by anti-cheat bypasses
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import glob
import html
import json
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


DEFAULT_IOC_PATH = Path("indicators/default_iocs.json")


def get_default_report_dir() -> Path:
    # Optional override for deployments/labs.
    env_override = os.environ.get("PC_CHECKER_REPORT_DIR")
    if env_override:
        return Path(env_override).expanduser()

    user_home = Path(os.environ.get("USERPROFILE", "~")).expanduser()
    onedrive_root = os.environ.get("OneDrive")

    candidates: List[Path] = []
    if onedrive_root:
        candidates.append(Path(onedrive_root) / "Documents" / "github" / "pc-checker")
    candidates.append(user_home / "OneDrive" / "Documents" / "github" / "pc-checker")
    candidates.append(user_home / "Documents" / "github" / "pc-checker")
    candidates.append(Path("reports"))

    return candidates[0]


DEFAULT_REPORT_DIR = get_default_report_dir()
DEFAULT_JSON_OUT = DEFAULT_REPORT_DIR / "latest_report.json"
DEFAULT_HTML_OUT = DEFAULT_REPORT_DIR / "latest_report.html"


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    matched_on: str
    evidence: str
    source: str


def run_command(command: List[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def powershell_json(command: str, timeout: int = 40) -> List[Dict[str, Any]]:
    wrapped = (
        "$ErrorActionPreference='Stop';"
        f"$d=({command});"
        "if($null -eq $d){'[]'} else {$d | ConvertTo-Json -Depth 5 -Compress}"
    )
    proc = run_command(["powershell", "-NoProfile", "-Command", wrapped], timeout=timeout)
    if proc.returncode != 0:
        return []
    raw = proc.stdout.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def ci_match(value: str, pattern: str) -> bool:
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def regex_match(value: str, pattern: str) -> bool:
    try:
        return re.search(pattern, value, flags=re.IGNORECASE) is not None
    except re.error:
        return False


def load_iocs(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"IOC file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("IOC JSON must be an object")
    return data


def get_processes() -> List[Dict[str, Any]]:
    records = powershell_json(
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,Name,ExecutablePath,CommandLine"
    )
    if records:
        return records

    # Fallback to tasklist if CIM fails.
    proc = run_command(["tasklist", "/fo", "csv", "/nh"])
    if proc.returncode != 0:
        return []
    out: List[Dict[str, Any]] = []
    reader = csv.reader(proc.stdout.splitlines())
    for row in reader:
        if not row:
            continue
        name = row[0] if len(row) > 0 else ""
        pid = row[1] if len(row) > 1 else ""
        out.append(
            {
                "ProcessId": pid.replace('"', ""),
                "Name": name.replace('"', ""),
                "ExecutablePath": "",
                "CommandLine": "",
            }
        )
    return out


def get_services() -> List[Dict[str, Any]]:
    return powershell_json(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName"
    )


def parse_reg_query_output(raw: str) -> List[Dict[str, str]]:
    lines = raw.splitlines()
    entries: List[Dict[str, str]] = []
    current_key = ""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.upper().startswith("HKEY_"):
            current_key = stripped
            continue
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) < 3:
            continue
        entries.append({"key": current_key, "name": parts[0], "type": parts[1], "data": parts[2]})
    return entries


def get_startup_registry_entries() -> List[Dict[str, str]]:
    keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    all_entries: List[Dict[str, str]] = []
    for key in keys:
        proc = run_command(["reg", "query", key])
        if proc.returncode == 0:
            all_entries.extend(parse_reg_query_output(proc.stdout))
    return all_entries


def get_boot_config() -> Dict[str, str]:
    proc = run_command(["bcdedit", "/enum"])
    if proc.returncode != 0:
        return {}
    flags = {}
    for line in proc.stdout.splitlines():
        l = line.strip()
        if not l:
            continue
        parts = re.split(r"\s{2,}", l)
        if len(parts) < 2:
            continue
        key = parts[0].strip().lower()
        val = parts[1].strip().lower()
        if key in {"testsigning", "nointegritychecks", "debug"}:
            flags[key] = val
    return flags


def expand_glob_pattern(pattern: str) -> str:
    expanded = os.path.expandvars(pattern)
    expanded = os.path.expanduser(expanded)
    return expanded


def glob_limited(pattern: str, limit: int) -> List[str]:
    expanded = expand_glob_pattern(pattern)
    matches = glob.glob(expanded, recursive=True)
    if not matches:
        return []
    matches = sorted(set(matches))
    if len(matches) > limit:
        return matches[:limit]
    return matches


def match_rule_strings(
    findings: List[Finding],
    category: str,
    rules: Iterable[Dict[str, Any]],
    values: Iterable[Dict[str, str]],
    value_getter,
) -> None:
    for rule in rules:
        pattern = normalize_text(rule.get("pattern"))
        if not pattern:
            continue
        rule_id = normalize_text(rule.get("id")) or f"{category}:{pattern}"
        severity = normalize_text(rule.get("severity")) or "medium"
        description = normalize_text(rule.get("description")) or "Rule matched"
        mode = normalize_text(rule.get("mode")) or "wildcard"
        target_field = normalize_text(rule.get("target_field")) or "value"

        for value in values:
            candidate = normalize_text(value_getter(value, target_field))
            if not candidate:
                continue

            matched = regex_match(candidate, pattern) if mode == "regex" else ci_match(candidate, pattern)
            if matched:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        description=description,
                        matched_on=target_field,
                        evidence=candidate,
                        source=normalize_text(value),
                    )
                )


def match_process_rules(iocs: Dict[str, Any], findings: List[Finding], processes: List[Dict[str, Any]]) -> None:
    proc_rules = iocs.get("process_rules", [])
    if not isinstance(proc_rules, list):
        return

    def get_proc_field(item: Dict[str, Any], target_field: str) -> str:
        mapping = {
            "name": normalize_text(item.get("Name")),
            "path": normalize_text(item.get("ExecutablePath")),
            "cmdline": normalize_text(item.get("CommandLine")),
            "value": " ".join(
                [
                    normalize_text(item.get("Name")),
                    normalize_text(item.get("ExecutablePath")),
                    normalize_text(item.get("CommandLine")),
                ]
            ).strip(),
        }
        return mapping.get(target_field, mapping["value"])

    match_rule_strings(findings, "process", proc_rules, processes, get_proc_field)


def match_service_rules(iocs: Dict[str, Any], findings: List[Finding], services: List[Dict[str, Any]]) -> None:
    svc_rules = iocs.get("service_rules", [])
    if not isinstance(svc_rules, list):
        return

    def get_service_field(item: Dict[str, Any], target_field: str) -> str:
        mapping = {
            "name": normalize_text(item.get("Name")),
            "display_name": normalize_text(item.get("DisplayName")),
            "path": normalize_text(item.get("PathName")),
            "state": normalize_text(item.get("State")),
            "value": " ".join(
                [
                    normalize_text(item.get("Name")),
                    normalize_text(item.get("DisplayName")),
                    normalize_text(item.get("PathName")),
                    normalize_text(item.get("State")),
                ]
            ).strip(),
        }
        return mapping.get(target_field, mapping["value"])

    match_rule_strings(findings, "service", svc_rules, services, get_service_field)


def match_registry_rules(iocs: Dict[str, Any], findings: List[Finding], entries: List[Dict[str, str]]) -> None:
    reg_rules = iocs.get("registry_rules", [])
    if not isinstance(reg_rules, list):
        return

    def get_reg_field(item: Dict[str, str], target_field: str) -> str:
        mapping = {
            "key": normalize_text(item.get("key")),
            "name": normalize_text(item.get("name")),
            "data": normalize_text(item.get("data")),
            "value": " ".join(
                [
                    normalize_text(item.get("key")),
                    normalize_text(item.get("name")),
                    normalize_text(item.get("data")),
                ]
            ).strip(),
        }
        return mapping.get(target_field, mapping["value"])

    match_rule_strings(findings, "registry", reg_rules, entries, get_reg_field)


def match_file_rules(
    iocs: Dict[str, Any],
    findings: List[Finding],
    path_match_limit: int,
    suppress_existence_check: bool = False,
) -> None:
    file_rules = iocs.get("file_rules", [])
    if not isinstance(file_rules, list):
        return

    for rule in file_rules:
        pattern = normalize_text(rule.get("pattern"))
        if not pattern:
            continue
        rule_id = normalize_text(rule.get("id")) or f"file:{pattern}"
        severity = normalize_text(rule.get("severity")) or "medium"
        description = normalize_text(rule.get("description")) or "File path rule matched"
        mode = normalize_text(rule.get("mode")) or "glob"

        if mode == "exact":
            p = Path(expand_glob_pattern(pattern))
            if suppress_existence_check or p.exists():
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="file",
                        severity=severity,
                        description=description,
                        matched_on="path",
                        evidence=str(p),
                        source=str(rule),
                    )
                )
            continue

        matches = glob_limited(pattern, path_match_limit)
        for m in matches:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category="file",
                    severity=severity,
                    description=description,
                    matched_on="path",
                    evidence=m,
                    source=str(rule),
                )
            )


def match_boot_rules(iocs: Dict[str, Any], findings: List[Finding], boot_flags: Dict[str, str]) -> None:
    boot_rules = iocs.get("boot_rules", [])
    if not isinstance(boot_rules, list):
        return
    if not boot_flags:
        return
    for rule in boot_rules:
        key = normalize_text(rule.get("key")).lower()
        expected = normalize_text(rule.get("expected")).lower()
        if not key or key not in boot_flags:
            continue
        actual = boot_flags.get(key, "")
        if actual == expected:
            findings.append(
                Finding(
                    rule_id=normalize_text(rule.get("id")) or f"boot:{key}={expected}",
                    category="boot_config",
                    severity=normalize_text(rule.get("severity")) or "high",
                    description=normalize_text(rule.get("description")) or "Boot config bypass indicator matched",
                    matched_on=key,
                    evidence=f"{key}={actual}",
                    source=str(rule),
                )
            )


def sort_findings(findings: List[Finding]) -> List[Finding]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda x: (rank.get(x.severity.lower(), 99), x.category, x.rule_id, x.evidence.lower()))


def summarize_findings(findings: List[Finding]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {"severity": {}, "category": {}}
    for f in findings:
        s = f.severity.lower()
        c = f.category.lower()
        out["severity"][s] = out["severity"].get(s, 0) + 1
        out["category"][c] = out["category"].get(c, 0) + 1
    return out


def print_console_report(findings: List[Finding], summary: Dict[str, Dict[str, int]], elapsed_s: float, limit: int) -> None:
    print("")
    print("=== FiveM Defensive Scanner Report ===")
    print(f"Host: {platform.node()}  OS: {platform.platform()}")
    print(f"Scan finished in {elapsed_s:.2f}s")
    print(f"Total findings: {len(findings)}")
    print("")
    print("Severity counts:")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary["severity"].get(sev, 0)
        if count:
            print(f"  - {sev}: {count}")
    print("")
    print("Category counts:")
    for cat, count in sorted(summary["category"].items()):
        print(f"  - {cat}: {count}")

    print("")
    print(f"Top findings (max {limit}):")
    for finding in findings[:limit]:
        print(
            f"  [{finding.severity.upper()}] {finding.category} | {finding.rule_id} | "
            f"{finding.description} | evidence: {finding.evidence}"
        )

    if not findings:
        print("  No IOC matches were found.")


def write_json_report(path: Path, findings: List[Finding], summary: Dict[str, Dict[str, int]], ioc_file: str, elapsed_s: float) -> None:
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "platform": platform.platform(),
        "ioc_file": ioc_file,
        "duration_seconds": round(elapsed_s, 3),
        "summary": summary,
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def severity_class(severity: str) -> str:
    sev = severity.lower()
    if sev in {"critical", "high", "medium", "low", "info"}:
        return sev
    return "unknown"


def write_html_report(path: Path, findings: List[Finding], summary: Dict[str, Dict[str, int]], ioc_file: str, elapsed_s: float) -> None:
    created = datetime.now(timezone.utc).isoformat()
    host = platform.node()
    platform_name = platform.platform()

    category_items = "".join(
        f"<li><strong>{html.escape(cat)}</strong>: {count}</li>"
        for cat, count in sorted(summary["category"].items())
    )
    if not category_items:
        category_items = "<li>No category matches.</li>"

    severity_items = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary["severity"].get(sev, 0)
        if count:
            severity_items.append(f'<li><span class="badge {sev}">{sev}</span> {count}</li>')
    severity_html = "".join(severity_items) if severity_items else "<li>No severity matches.</li>"

    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td><span class='badge {severity_class(f.severity)}'>{html.escape(f.severity.upper())}</span></td>"
            f"<td>{html.escape(f.category)}</td>"
            f"<td>{html.escape(f.rule_id)}</td>"
            f"<td>{html.escape(f.description)}</td>"
            f"<td><code>{html.escape(f.matched_on)}</code></td>"
            f"<td><code>{html.escape(f.evidence)}</code></td>"
            "</tr>"
        )
    rows_html = "".join(rows)
    if not rows_html:
        rows_html = (
            "<tr><td colspan='6'>No IOC matches were found for this scan.</td></tr>"
        )

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FiveM Defensive Scanner Report</title>
  <style>
    :root {{
      --bg: #f6f8fb;
      --panel: #ffffff;
      --text: #1f2a37;
      --sub: #5b6777;
      --border: #d9e0ea;
      --critical: #8b0000;
      --high: #a23b12;
      --medium: #935f00;
      --low: #15603d;
      --info: #005a8d;
      --unknown: #4b5563;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: linear-gradient(180deg, #ecf2ff 0%, var(--bg) 60%);
      color: var(--text);
      font-family: "Segoe UI", Tahoma, sans-serif;
      line-height: 1.4;
      padding: 20px;
    }}
    .wrap {{
      max-width: 1200px;
      margin: 0 auto;
      display: grid;
      gap: 14px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      box-shadow: 0 8px 24px rgba(16, 24, 40, 0.06);
    }}
    h1, h2 {{
      margin: 0 0 10px;
      line-height: 1.2;
    }}
    h1 {{ font-size: 1.35rem; }}
    h2 {{ font-size: 1.05rem; }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 6px 16px;
      color: var(--sub);
      font-size: 0.93rem;
    }}
    ul {{
      margin: 8px 0 0;
      padding-left: 18px;
    }}
    .two-col {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 14px;
    }}
    .table-wrap {{
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 860px;
      background: #fff;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      font-size: 0.92rem;
    }}
    th {{
      position: sticky;
      top: 0;
      background: #eef3fa;
      z-index: 1;
    }}
    code {{
      background: #eef3fa;
      border: 1px solid #d8e2f1;
      border-radius: 6px;
      padding: 1px 5px;
      word-break: break-word;
    }}
    .badge {{
      display: inline-block;
      min-width: 68px;
      text-align: center;
      color: #fff;
      font-weight: 600;
      border-radius: 999px;
      padding: 2px 8px;
      letter-spacing: 0.2px;
      font-size: 0.75rem;
      text-transform: uppercase;
    }}
    .critical {{ background: var(--critical); }}
    .high {{ background: var(--high); }}
    .medium {{ background: var(--medium); }}
    .low {{ background: var(--low); }}
    .info {{ background: var(--info); }}
    .unknown {{ background: var(--unknown); }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="panel">
      <h1>FiveM Defensive Scanner Report</h1>
      <div class="meta">
        <div><strong>Created (UTC):</strong> {html.escape(created)}</div>
        <div><strong>Host:</strong> {html.escape(host)}</div>
        <div><strong>Platform:</strong> {html.escape(platform_name)}</div>
        <div><strong>IOC file:</strong> {html.escape(ioc_file)}</div>
        <div><strong>Duration:</strong> {elapsed_s:.3f}s</div>
        <div><strong>Total findings:</strong> {len(findings)}</div>
      </div>
    </section>

    <section class="two-col">
      <div class="panel">
        <h2>Severity Summary</h2>
        <ul>
          {severity_html}
        </ul>
      </div>
      <div class="panel">
        <h2>Category Summary</h2>
        <ul>
          {category_items}
        </ul>
      </div>
    </section>

    <section class="panel">
      <h2>Detections</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Category</th>
              <th>Rule ID</th>
              <th>Description</th>
              <th>Matched On</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </section>
  </div>
</body>
</html>
"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_doc, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="FiveM defensive cheat/bypass artifact scanner (authorized forensic/admin use only)."
    )
    parser.add_argument(
        "--ioc",
        default=str(DEFAULT_IOC_PATH),
        help=f"Path to IOC/rule JSON (default: {DEFAULT_IOC_PATH})",
    )
    parser.add_argument(
        "--json-out",
        default=str(DEFAULT_JSON_OUT),
        help=f"Output path for JSON report (default: {DEFAULT_JSON_OUT})",
    )
    parser.add_argument(
        "--html-out",
        default=str(DEFAULT_HTML_OUT),
        help=f"Output path for HTML report (default: {DEFAULT_HTML_OUT})",
    )
    parser.add_argument(
        "--print-limit",
        type=int,
        default=25,
        help="Number of findings to print to console (default: 25)",
    )
    parser.add_argument(
        "--glob-limit",
        type=int,
        default=50,
        help="Max matches to keep per file glob rule (default: 50)",
    )
    parser.add_argument(
        "--skip-processes",
        action="store_true",
        help="Skip process checks",
    )
    parser.add_argument(
        "--skip-services",
        action="store_true",
        help="Skip service checks",
    )
    parser.add_argument(
        "--skip-registry",
        action="store_true",
        help="Skip startup registry checks",
    )
    parser.add_argument(
        "--skip-files",
        action="store_true",
        help="Skip file path checks",
    )
    parser.add_argument(
        "--skip-boot",
        action="store_true",
        help="Skip boot configuration checks",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    start = time.time()

    try:
        iocs = load_iocs(Path(args.ioc))
    except Exception as exc:
        print(f"[ERROR] Failed to load IOC file: {exc}", file=sys.stderr)
        return 2

    findings: List[Finding] = []

    if not args.skip_processes:
        processes = get_processes()
        match_process_rules(iocs, findings, processes)

    if not args.skip_services:
        services = get_services()
        match_service_rules(iocs, findings, services)

    if not args.skip_registry:
        reg_entries = get_startup_registry_entries()
        match_registry_rules(iocs, findings, reg_entries)

    if not args.skip_files:
        match_file_rules(iocs, findings, path_match_limit=max(1, args.glob_limit))

    if not args.skip_boot:
        boot_flags = get_boot_config()
        match_boot_rules(iocs, findings, boot_flags)

    findings = sort_findings(findings)
    summary = summarize_findings(findings)
    elapsed = time.time() - start
    print_console_report(findings, summary, elapsed, max(1, args.print_limit))

    out_path = Path(args.json_out)
    try:
        write_json_report(out_path, findings, summary, args.ioc, elapsed)
        print(f"\nJSON report written to: {out_path}")
    except Exception as exc:
        print(f"[WARN] Failed to write JSON report: {exc}", file=sys.stderr)
        return 1

    html_out_path = Path(args.html_out)
    try:
        write_html_report(html_out_path, findings, summary, args.ioc, elapsed)
        print(f"HTML report written to: {html_out_path}")
    except Exception as exc:
        print(f"[WARN] Failed to write HTML report: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
