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
 - unusual/unsigned running program anomalies
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
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple


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
DEFAULT_PROGRAM_HTML_OUT = DEFAULT_REPORT_DIR / "program_anomalies.html"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    matched_on: str
    evidence: str
    source: str


@dataclass
class ProgramAnomaly:
    process_id: str
    process_name: str
    executable_path: str
    command_line: str
    signature_status: str
    publisher: str
    severity: str
    reasons: List[str]
    matched_rules: List[str]


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


def chunked(values: List[str], size: int) -> Iterable[List[str]]:
    step = max(1, size)
    for index in range(0, len(values), step):
        yield values[index:index + step]


def severity_max(left: str, right: str) -> str:
    if SEVERITY_RANK.get(right.lower(), 99) < SEVERITY_RANK.get(left.lower(), 99):
        return right
    return left


def normalize_path(path: str) -> str:
    return normalize_text(path).replace("/", "\\").strip().lower()


def path_matches_any(path: str, patterns: List[str]) -> bool:
    normalized = normalize_path(path)
    for pattern in patterns:
        if ci_match(normalized, normalize_path(pattern)):
            return True
    return False


def get_signature_details_for_paths(paths: List[str], chunk_size: int = 45) -> Dict[str, Dict[str, str]]:
    result: Dict[str, Dict[str, str]] = {}
    unique_paths = sorted({normalize_text(p) for p in paths if normalize_text(p)}, key=lambda x: x.lower())
    if not unique_paths:
        return result

    for path_chunk in chunked(unique_paths, chunk_size):
        quoted_paths = ",".join("'" + p.replace("'", "''") + "'" for p in path_chunk)
        command = (
            f"$paths=@({quoted_paths});"
            "$out=@();"
            "foreach($p in $paths){"
            "  if(Test-Path -LiteralPath $p){"
            "    try {"
            "      $sig=Get-AuthenticodeSignature -LiteralPath $p;"
            "      $pub=''; if($sig.SignerCertificate){$pub=[string]$sig.SignerCertificate.Subject};"
            "      $out += [PSCustomObject]@{Path=$p;Status=[string]$sig.Status;Publisher=$pub;StatusMessage=[string]$sig.StatusMessage};"
            "    } catch {"
            "      $out += [PSCustomObject]@{Path=$p;Status='LookupError';Publisher='';StatusMessage=[string]$_.Exception.Message};"
            "    }"
            "  } else {"
            "    $out += [PSCustomObject]@{Path=$p;Status='MissingFile';Publisher='';StatusMessage='Executable path not found'};"
            "  }"
            "};"
            "$out"
        )

        records = powershell_json(command, timeout=180)
        for record in records:
            record_path = normalize_text(record.get("Path"))
            if not record_path:
                continue
            result[normalize_path(record_path)] = {
                "status": normalize_text(record.get("Status")) or "Unknown",
                "publisher": normalize_text(record.get("Publisher")),
                "status_message": normalize_text(record.get("StatusMessage")),
            }

    return result


def get_program_anomaly_rules(iocs: Dict[str, Any]) -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "suspicious_path_patterns": [
            r"C:\Users\*\AppData\Local\Temp\*.exe",
            r"C:\Users\*\AppData\Roaming\*.exe",
            r"C:\Users\*\Downloads\*.exe",
            r"C:\Users\*\Desktop\*.exe",
            r"C:\ProgramData\*.exe",
            r"C:\Windows\Temp\*.exe",
            r"C:\$Recycle.Bin\*\*.exe",
        ],
        "trusted_path_patterns": [
            r"C:\Windows\*.exe",
            r"C:\Windows\System32\*.exe",
            r"C:\Windows\SysWOW64\*.exe",
            r"C:\Program Files\*\*.exe",
            r"C:\Program Files (x86)\*\*.exe",
        ],
        "critical_signature_statuses": ["HashMismatch", "NotTrusted", "LookupError"],
        "unsigned_signature_statuses": ["NotSigned", "UnknownError", "NotSupportedFileFormat", "MissingFile"],
        "trusted_publisher_keywords": [
            "microsoft",
            "nvidia",
            "amd",
            "intel",
            "google",
            "valve",
            "discord",
            "epic games",
            "rockstar games",
            "take-two",
        ],
        "name_regex_rules": [
            {
                "id": "name_random_hex",
                "pattern": r"^[a-f0-9]{8,}\.exe$",
                "severity": "medium",
                "description": "Process name appears random/hex-like",
            },
            {
                "id": "name_guid_like",
                "pattern": r"^\{?[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12}\}?\.exe$",
                "severity": "high",
                "description": "Process name resembles a GUID-like executable",
            },
        ],
        "cmdline_regex_rules": [
            {
                "id": "cmd_powershell_encoded",
                "pattern": r"powershell(\.exe)?\s+.*(-enc|-encodedcommand)\s+",
                "severity": "high",
                "description": "Encoded PowerShell command line detected",
            },
            {
                "id": "cmd_hidden_window",
                "pattern": r"(-windowstyle|/windowstyle)\s+hidden|(-w|/w)\s+hidden",
                "severity": "medium",
                "description": "Hidden window execution flag detected",
            },
        ],
        "custom_rules": [],
    }

    ioc_rules = iocs.get("program_anomaly_rules")
    if isinstance(ioc_rules, dict):
        for key, value in ioc_rules.items():
            if isinstance(value, list) and value:
                defaults[key] = value
    return defaults


def get_process_field(process: Dict[str, Any], field: str) -> str:
    mapping = {
        "name": normalize_text(process.get("Name")),
        "path": normalize_text(process.get("ExecutablePath")),
        "cmdline": normalize_text(process.get("CommandLine")),
        "value": " ".join(
            [
                normalize_text(process.get("Name")),
                normalize_text(process.get("ExecutablePath")),
                normalize_text(process.get("CommandLine")),
            ]
        ).strip(),
    }
    return mapping.get(field, mapping["value"])


def detect_program_anomalies(iocs: Dict[str, Any], processes: List[Dict[str, Any]]) -> List[ProgramAnomaly]:
    if not processes:
        return []

    rules = get_program_anomaly_rules(iocs)
    suspicious_paths = [expand_glob_pattern(p) for p in rules.get("suspicious_path_patterns", [])]
    trusted_paths = [expand_glob_pattern(p) for p in rules.get("trusted_path_patterns", [])]
    critical_signature_statuses = {
        normalize_text(status).lower() for status in rules.get("critical_signature_statuses", [])
    }
    unsigned_signature_statuses = {
        normalize_text(status).lower() for status in rules.get("unsigned_signature_statuses", [])
    }
    trusted_publisher_keywords = [
        normalize_text(keyword).lower() for keyword in rules.get("trusted_publisher_keywords", [])
    ]

    executable_paths = [
        normalize_text(process.get("ExecutablePath"))
        for process in processes
        if normalize_text(process.get("ExecutablePath"))
    ]
    signature_map = get_signature_details_for_paths(executable_paths)

    anomalies: List[ProgramAnomaly] = []
    seen_keys: Set[Tuple[str, str, str]] = set()

    for process in processes:
        process_id = normalize_text(process.get("ProcessId"))
        process_name = normalize_text(process.get("Name")) or "<unknown>"
        executable_path = normalize_text(process.get("ExecutablePath"))
        command_line = normalize_text(process.get("CommandLine"))
        if not executable_path:
            continue

        signature = signature_map.get(normalize_path(executable_path), {})
        signature_status = normalize_text(signature.get("status")) or "Unknown"
        publisher = normalize_text(signature.get("publisher"))
        status_message = normalize_text(signature.get("status_message"))

        reasons: List[str] = []
        matched_rules: List[str] = []
        severity = "low"

        if path_matches_any(executable_path, suspicious_paths):
            reasons.append("Executable is running from a user-writable or unusual directory")
            matched_rules.append("path_suspicious_location")
            severity = severity_max(severity, "high")

        status_lower = signature_status.lower()
        trusted_location = path_matches_any(executable_path, trusted_paths)
        if status_lower in critical_signature_statuses:
            reasons.append(f"Signature status is {signature_status} ({status_message or 'trust verification failed'})")
            matched_rules.append("signature_critical_status")
            severity = severity_max(severity, "critical")
        elif status_lower in unsigned_signature_statuses:
            if trusted_location:
                reasons.append(f"Signature status is {signature_status}")
                matched_rules.append("signature_unsigned_trusted_location")
                severity = severity_max(severity, "medium")
            else:
                reasons.append(f"Signature status is {signature_status} outside common trusted program folders")
                matched_rules.append("signature_unsigned_untrusted_location")
                severity = severity_max(severity, "high")

        if signature_status.lower() == "valid":
            if not publisher:
                reasons.append("Signature is valid but publisher information is missing")
                matched_rules.append("signature_valid_missing_publisher")
                severity = severity_max(severity, "medium")
            elif not any(keyword in publisher.lower() for keyword in trusted_publisher_keywords):
                if path_matches_any(executable_path, suspicious_paths):
                    reasons.append("Signed executable has an uncommon publisher and suspicious execution path")
                    matched_rules.append("publisher_uncommon_suspicious_path")
                    severity = severity_max(severity, "medium")

        executable_name = Path(executable_path).name
        for rule in rules.get("name_regex_rules", []):
            pattern = normalize_text(rule.get("pattern"))
            if pattern and regex_match(executable_name, pattern):
                reasons.append(normalize_text(rule.get("description")) or "Suspicious executable naming pattern")
                matched_rules.append(normalize_text(rule.get("id")) or "name_regex_rule")
                severity = severity_max(severity, normalize_text(rule.get("severity")) or "medium")

        for rule in rules.get("cmdline_regex_rules", []):
            pattern = normalize_text(rule.get("pattern"))
            if command_line and pattern and regex_match(command_line, pattern):
                reasons.append(normalize_text(rule.get("description")) or "Suspicious process command line pattern")
                matched_rules.append(normalize_text(rule.get("id")) or "cmdline_regex_rule")
                severity = severity_max(severity, normalize_text(rule.get("severity")) or "medium")

        for rule in rules.get("custom_rules", []):
            if not isinstance(rule, dict):
                continue
            pattern = normalize_text(rule.get("pattern"))
            if not pattern:
                continue
            mode = normalize_text(rule.get("mode")) or "wildcard"
            target_field = normalize_text(rule.get("target_field")) or "value"
            candidate = get_process_field(process, target_field)
            matched = regex_match(candidate, pattern) if mode == "regex" else ci_match(candidate, pattern)
            if matched:
                reasons.append(normalize_text(rule.get("description")) or "Custom program anomaly rule matched")
                matched_rules.append(normalize_text(rule.get("id")) or "custom_program_rule")
                severity = severity_max(severity, normalize_text(rule.get("severity")) or "medium")

        if not reasons:
            continue

        dedupe_key = (process_id, normalize_path(executable_path), ",".join(sorted(set(matched_rules))))
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)

        anomalies.append(
            ProgramAnomaly(
                process_id=process_id,
                process_name=process_name,
                executable_path=executable_path,
                command_line=command_line,
                signature_status=signature_status,
                publisher=publisher,
                severity=severity.lower(),
                reasons=sorted(set(reasons)),
                matched_rules=sorted(set(matched_rules)),
            )
        )

    return sorted(
        anomalies,
        key=lambda anomaly: (
            SEVERITY_RANK.get(anomaly.severity.lower(), 99),
            anomaly.process_name.lower(),
            anomaly.executable_path.lower(),
            anomaly.process_id,
        ),
    )


def merge_program_anomalies_into_findings(findings: List[Finding], anomalies: List[ProgramAnomaly]) -> None:
    for anomaly in anomalies:
        findings.append(
            Finding(
                rule_id="program_anomaly",
                category="program_anomaly",
                severity=anomaly.severity,
                description="; ".join(anomaly.reasons),
                matched_on="executable_path",
                evidence=anomaly.executable_path,
                source=(
                    f"pid={anomaly.process_id};name={anomaly.process_name};"
                    f"signature={anomaly.signature_status};publisher={anomaly.publisher}"
                ),
            )
        )


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
    return sorted(
        findings,
        key=lambda x: (SEVERITY_RANK.get(x.severity.lower(), 99), x.category, x.rule_id, x.evidence.lower()),
    )


def summarize_findings(findings: List[Finding]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {"severity": {}, "category": {}}
    for f in findings:
        s = f.severity.lower()
        c = f.category.lower()
        out["severity"][s] = out["severity"].get(s, 0) + 1
        out["category"][c] = out["category"].get(c, 0) + 1
    return out


def print_console_report(
    findings: List[Finding],
    summary: Dict[str, Dict[str, int]],
    elapsed_s: float,
    limit: int,
    program_anomalies: List[ProgramAnomaly],
) -> None:
    print("")
    print("=== FiveM Defensive Scanner Report ===")
    print(f"Host: {platform.node()}  OS: {platform.platform()}")
    print(f"Scan finished in {elapsed_s:.2f}s")
    print(f"Total findings: {len(findings)}")
    print(f"Program anomalies: {len(program_anomalies)}")
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

    if program_anomalies:
        print("")
        print("Top unusual/unsigned programs:")
        for anomaly in program_anomalies[: min(limit, 10)]:
            reason_preview = anomaly.reasons[0] if anomaly.reasons else "Program anomaly"
            print(
                f"  [{anomaly.severity.upper()}] {anomaly.process_name} (PID {anomaly.process_id}) | "
                f"{anomaly.signature_status} | {anomaly.executable_path} | {reason_preview}"
            )


def write_json_report(
    path: Path,
    findings: List[Finding],
    summary: Dict[str, Dict[str, int]],
    ioc_file: str,
    elapsed_s: float,
    program_anomalies: List[ProgramAnomaly],
) -> None:
    program_severity_counts = Counter([anomaly.severity.lower() for anomaly in program_anomalies])
    signature_status_counts = Counter([anomaly.signature_status for anomaly in program_anomalies])
    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "platform": platform.platform(),
        "ioc_file": ioc_file,
        "duration_seconds": round(elapsed_s, 3),
        "summary": summary,
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
        "program_anomaly_count": len(program_anomalies),
        "program_anomaly_summary": {
            "severity": dict(program_severity_counts),
            "signature_status": dict(signature_status_counts),
        },
        "program_anomalies": [asdict(a) for a in program_anomalies],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def severity_class(severity: str) -> str:
    sev = severity.lower()
    if sev in {"critical", "high", "medium", "low", "info"}:
        return sev
    return "unknown"


def build_report_css() -> str:
    return """
    :root {
      --bg: #eef4fb;
      --panel: #ffffff;
      --panel-2: #f8fbff;
      --text: #182230;
      --muted: #536173;
      --border: #dbe5f2;
      --critical: #8f1f1f;
      --high: #b34b1a;
      --medium: #8f6d15;
      --low: #157252;
      --info: #0f5f9a;
      --unknown: #505f73;
      --focus: #1f79d2;
      --shadow: 0 12px 32px rgba(22, 35, 58, 0.08);
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; scroll-behavior: smooth; }
    body {
      background:
        radial-gradient(1100px 420px at 90% -10%, rgba(31, 121, 210, 0.2), transparent 70%),
        radial-gradient(900px 380px at -20% 0%, rgba(52, 185, 145, 0.15), transparent 70%),
        var(--bg);
      color: var(--text);
      font-family: "Segoe UI", "Trebuchet MS", Tahoma, sans-serif;
      line-height: 1.45;
      padding: 18px;
    }
    .wrap {
      max-width: 1280px;
      margin: 0 auto;
      display: grid;
      gap: 14px;
    }
    .panel {
      background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
      box-shadow: var(--shadow);
      animation: fadeUp .35s ease;
    }
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }
    h1, h2, h3 {
      margin: 0 0 10px;
      line-height: 1.2;
      letter-spacing: .1px;
    }
    h1 { font-size: 1.35rem; }
    h2 { font-size: 1.03rem; }
    h3 { font-size: .95rem; color: var(--muted); }
    .meta {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 6px 14px;
      color: var(--muted);
      font-size: .92rem;
    }
    .two-col {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 14px;
    }
    .controls {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-top: 8px;
    }
    label {
      display: block;
      font-size: .82rem;
      color: var(--muted);
      margin-bottom: 4px;
    }
    input[type="text"], select {
      width: 100%;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--text);
      border-radius: 10px;
      padding: 8px 10px;
      font-size: .9rem;
      transition: border-color .15s ease, box-shadow .15s ease;
      outline: none;
    }
    input[type="text"]:focus, select:focus {
      border-color: var(--focus);
      box-shadow: 0 0 0 3px rgba(31, 121, 210, 0.15);
    }
    ul {
      margin: 8px 0 0;
      padding-left: 18px;
    }
    .table-wrap {
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fff;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 980px;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      font-size: .9rem;
    }
    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #edf3fb;
      color: #344154;
    }
    tr {
      transition: background-color .15s ease, transform .15s ease;
    }
    tbody tr:hover {
      background: #f5f9ff;
    }
    code {
      background: #edf4ff;
      border: 1px solid #d7e4f8;
      border-radius: 6px;
      padding: 1px 6px;
      word-break: break-word;
    }
    .badge {
      display: inline-block;
      min-width: 72px;
      text-align: center;
      color: #fff;
      font-weight: 700;
      border-radius: 999px;
      padding: 2px 9px;
      letter-spacing: .25px;
      font-size: .72rem;
      text-transform: uppercase;
      box-shadow: inset 0 -2px 0 rgba(0,0,0,0.12);
    }
    .chip {
      display: inline-block;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--muted);
      padding: 2px 8px;
      font-size: .74rem;
      margin-right: 4px;
      margin-bottom: 4px;
    }
    .critical { background: var(--critical); }
    .high { background: var(--high); }
    .medium { background: var(--medium); }
    .low { background: var(--low); }
    .info { background: var(--info); }
    .unknown { background: var(--unknown); }
    .muted { color: var(--muted); }
    details > summary {
      cursor: pointer;
      color: var(--focus);
    }
    @media (max-width: 640px) {
      body { padding: 12px; }
      .panel { padding: 12px; }
      th, td { font-size: .84rem; padding: 8px 9px; }
      table { min-width: 760px; }
    }
    """


def write_html_report(
    path: Path,
    findings: List[Finding],
    summary: Dict[str, Dict[str, int]],
    ioc_file: str,
    elapsed_s: float,
    program_html_path: Path,
) -> None:
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
        search_blob = " ".join(
            [f.severity, f.category, f.rule_id, f.description, f.matched_on, f.evidence, f.source]
        ).lower()
        rows.append(
            "<tr "
            f"data-severity='{html.escape(severity_class(f.severity))}' "
            f"data-category='{html.escape(f.category.lower())}' "
            f"data-search='{html.escape(search_blob)}'>"
            f"<td><span class='badge {severity_class(f.severity)}'>{html.escape(f.severity.upper())}</span></td>"
            f"<td>{html.escape(f.category)}</td>"
            f"<td>{html.escape(f.rule_id)}</td>"
            f"<td>{html.escape(f.description)}</td>"
            f"<td><code>{html.escape(f.matched_on)}</code></td>"
            f"<td><code>{html.escape(f.evidence)}</code></td>"
            "</tr>"
        )
    rows_html = "".join(rows)
    no_rows_text = "No IOC matches were found for this scan."
    if not rows_html:
        rows_html = f"<tr id='noRows'><td colspan='6'>{no_rows_text}</td></tr>"
    else:
        rows_html += f"<tr id='noRows' style='display:none;'><td colspan='6'>{no_rows_text}</td></tr>"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FiveM Defensive Scanner Report</title>
  <style>
    {build_report_css()}
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
        <div><strong>Program anomaly page:</strong> <code>{html.escape(str(program_html_path))}</code></div>
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
      <div class="controls">
        <div>
          <label for="findingsSearch">Search</label>
          <input type="text" id="findingsSearch" placeholder="Search evidence, rule IDs, descriptions...">
        </div>
        <div>
          <label for="severityFilter">Severity</label>
          <select id="severityFilter">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>
      <div class="table-wrap">
        <table id="findingsTable">
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
  <script>
    (() => {{
      const rows = Array.from(document.querySelectorAll("#findingsTable tbody tr[data-severity]"));
      const searchInput = document.getElementById("findingsSearch");
      const severityFilter = document.getElementById("severityFilter");
      const noRows = document.getElementById("noRows");

      function applyFilters() {{
        const query = (searchInput?.value || "").trim().toLowerCase();
        const severity = (severityFilter?.value || "").trim().toLowerCase();
        let visibleRows = 0;

        rows.forEach((row) => {{
          const rowSeverity = (row.dataset.severity || "").toLowerCase();
          const rowSearch = (row.dataset.search || "").toLowerCase();
          const matchesSeverity = !severity || rowSeverity === severity;
          const matchesSearch = !query || rowSearch.includes(query);
          const visible = matchesSeverity && matchesSearch;
          row.style.display = visible ? "table-row" : "none";
          if (visible) visibleRows += 1;
        }});

        if (noRows) {{
          noRows.style.display = visibleRows === 0 ? "table-row" : "none";
        }}
      }}

      if (searchInput) searchInput.addEventListener("input", applyFilters);
      if (severityFilter) severityFilter.addEventListener("change", applyFilters);
      applyFilters();
    }})();
  </script>
</body>
</html>
"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_doc, encoding="utf-8")


def write_program_html_report(
    path: Path,
    anomalies: List[ProgramAnomaly],
    ioc_file: str,
    elapsed_s: float,
) -> None:
    created = datetime.now(timezone.utc).isoformat()
    host = platform.node()
    platform_name = platform.platform()
    severity_counts = Counter([a.severity.lower() for a in anomalies])
    signature_counts = Counter([a.signature_status for a in anomalies])

    severity_items = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count:
            severity_items.append(f'<li><span class="badge {sev}">{sev}</span> {count}</li>')
    severity_html = "".join(severity_items) if severity_items else "<li>No program anomalies matched.</li>"

    signature_items = "".join(
        f"<li><strong>{html.escape(signature)}</strong>: {count}</li>"
        for signature, count in signature_counts.most_common()
    )
    if not signature_items:
        signature_items = "<li>No signature anomalies matched.</li>"

    rows = []
    for anomaly in anomalies:
        search_blob = " ".join(
            [
                anomaly.process_name,
                anomaly.process_id,
                anomaly.executable_path,
                anomaly.signature_status,
                anomaly.publisher,
                " ".join(anomaly.reasons),
                " ".join(anomaly.matched_rules),
                anomaly.command_line,
            ]
        ).lower()
        reasons_html = "".join(f"<span class='chip'>{html.escape(reason)}</span>" for reason in anomaly.reasons)
        rules_html = "".join(f"<span class='chip'>{html.escape(rule)}</span>" for rule in anomaly.matched_rules)
        cmdline_html = (
            f"<details><summary>View command line</summary><code>{html.escape(anomaly.command_line)}</code></details>"
            if anomaly.command_line
            else "<span class='muted'>N/A</span>"
        )
        publisher_text = anomaly.publisher if anomaly.publisher else "N/A"

        rows.append(
            "<tr "
            f"data-severity='{html.escape(severity_class(anomaly.severity))}' "
            f"data-signature='{html.escape(anomaly.signature_status.lower())}' "
            f"data-search='{html.escape(search_blob)}'>"
            f"<td><span class='badge {severity_class(anomaly.severity)}'>{html.escape(anomaly.severity.upper())}</span></td>"
            f"<td>{html.escape(anomaly.process_name)}</td>"
            f"<td><code>{html.escape(anomaly.process_id)}</code></td>"
            f"<td><code>{html.escape(anomaly.signature_status)}</code></td>"
            f"<td>{html.escape(publisher_text)}</td>"
            f"<td><code>{html.escape(anomaly.executable_path)}</code></td>"
            f"<td>{reasons_html}</td>"
            f"<td>{rules_html}</td>"
            f"<td>{cmdline_html}</td>"
            "</tr>"
        )

    no_rows_text = "No unusual/unsigned program anomalies were detected."
    rows_html = "".join(rows)
    if not rows_html:
        rows_html = f"<tr id='noProgramRows'><td colspan='9'>{no_rows_text}</td></tr>"
    else:
        rows_html += f"<tr id='noProgramRows' style='display:none;'><td colspan='9'>{no_rows_text}</td></tr>"

    signature_filter_options = ["<option value=''>All signature states</option>"] + [
        f"<option value='{html.escape(signature.lower())}'>{html.escape(signature)}</option>"
        for signature in sorted(signature_counts.keys(), key=lambda x: x.lower())
    ]

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FiveM Program Anomaly Report</title>
  <style>
    {build_report_css()}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="panel">
      <h1>Unusual/Unsigned Program Report</h1>
      <div class="meta">
        <div><strong>Created (UTC):</strong> {html.escape(created)}</div>
        <div><strong>Host:</strong> {html.escape(host)}</div>
        <div><strong>Platform:</strong> {html.escape(platform_name)}</div>
        <div><strong>IOC file:</strong> {html.escape(ioc_file)}</div>
        <div><strong>Duration:</strong> {elapsed_s:.3f}s</div>
        <div><strong>Total anomalies:</strong> {len(anomalies)}</div>
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
        <h2>Signature Status Summary</h2>
        <ul>
          {signature_items}
        </ul>
      </div>
    </section>

    <section class="panel">
      <h2>Program Detections</h2>
      <div class="controls">
        <div>
          <label for="programSearch">Search</label>
          <input type="text" id="programSearch" placeholder="Search program name, path, reasons, command line...">
        </div>
        <div>
          <label for="programSeverityFilter">Severity</label>
          <select id="programSeverityFilter">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div>
          <label for="programSignatureFilter">Signature</label>
          <select id="programSignatureFilter">
            {"".join(signature_filter_options)}
          </select>
        </div>
      </div>
      <div class="table-wrap">
        <table id="programTable">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Process</th>
              <th>PID</th>
              <th>Signature Status</th>
              <th>Publisher</th>
              <th>Executable Path</th>
              <th>Reasons</th>
              <th>Matched Rules</th>
              <th>Command Line</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </section>
  </div>
  <script>
    (() => {{
      const rows = Array.from(document.querySelectorAll("#programTable tbody tr[data-severity]"));
      const searchInput = document.getElementById("programSearch");
      const severityFilter = document.getElementById("programSeverityFilter");
      const signatureFilter = document.getElementById("programSignatureFilter");
      const noRows = document.getElementById("noProgramRows");

      function applyFilters() {{
        const query = (searchInput?.value || "").trim().toLowerCase();
        const severity = (severityFilter?.value || "").trim().toLowerCase();
        const signature = (signatureFilter?.value || "").trim().toLowerCase();
        let visibleRows = 0;

        rows.forEach((row) => {{
          const rowSeverity = (row.dataset.severity || "").toLowerCase();
          const rowSignature = (row.dataset.signature || "").toLowerCase();
          const rowSearch = (row.dataset.search || "").toLowerCase();
          const matchesSeverity = !severity || rowSeverity === severity;
          const matchesSignature = !signature || rowSignature === signature;
          const matchesSearch = !query || rowSearch.includes(query);
          const visible = matchesSeverity && matchesSignature && matchesSearch;
          row.style.display = visible ? "table-row" : "none";
          if (visible) visibleRows += 1;
        }});

        if (noRows) {{
          noRows.style.display = visibleRows === 0 ? "table-row" : "none";
        }}
      }}

      if (searchInput) searchInput.addEventListener("input", applyFilters);
      if (severityFilter) severityFilter.addEventListener("change", applyFilters);
      if (signatureFilter) signatureFilter.addEventListener("change", applyFilters);
      applyFilters();
    }})();
  </script>
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
        "--program-html-out",
        default=str(DEFAULT_PROGRAM_HTML_OUT),
        help=f"Output path for unusual/unsigned program HTML report (default: {DEFAULT_PROGRAM_HTML_OUT})",
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
    parser.add_argument(
        "--skip-program-anomalies",
        action="store_true",
        help="Skip unusual/unsigned program anomaly checks",
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
    program_anomalies: List[ProgramAnomaly] = []
    processes: List[Dict[str, Any]] = []

    if (not args.skip_processes) or (not args.skip_program_anomalies):
        processes = get_processes()

    if not args.skip_processes:
        match_process_rules(iocs, findings, processes)

    if not args.skip_program_anomalies:
        program_anomalies = detect_program_anomalies(iocs, processes)
        merge_program_anomalies_into_findings(findings, program_anomalies)

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
    print_console_report(findings, summary, elapsed, max(1, args.print_limit), program_anomalies)

    out_path = Path(args.json_out)
    try:
        write_json_report(out_path, findings, summary, args.ioc, elapsed, program_anomalies)
        print(f"\nJSON report written to: {out_path}")
    except Exception as exc:
        print(f"[WARN] Failed to write JSON report: {exc}", file=sys.stderr)
        return 1

    html_out_path = Path(args.html_out)
    program_html_out_path = Path(args.program_html_out)
    try:
        write_html_report(html_out_path, findings, summary, args.ioc, elapsed, program_html_out_path)
        print(f"HTML report written to: {html_out_path}")
    except Exception as exc:
        print(f"[WARN] Failed to write HTML report: {exc}", file=sys.stderr)
        return 1

    try:
        write_program_html_report(program_html_out_path, program_anomalies, args.ioc, elapsed)
        print(f"Program anomaly HTML report written to: {program_html_out_path}")
    except Exception as exc:
        print(f"[WARN] Failed to write program anomaly HTML report: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
