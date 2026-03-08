# FiveM PC Checker (Defensive Scanner)

Windows-based forensic scanner for detecting suspicious cheat/bypass artifacts on systems used for FiveM.

## What it does

The scanner checks for IOC/rule matches across:
- Running processes (name/path/command line)
- Services (name/display/path/state)
- Startup registry locations
- File-system artifacts (glob/exact path rules)
- Boot configuration flags often associated with bypass activity
- Unusual or unsigned running program anomalies (signature status + path/behavior heuristics)

Outputs:
- JSON report
- Main HTML detections report
- Separate HTML report focused on unusual/unsigned programs

## Important note

This project is for authorized defensive and forensic use.  
No scanner can guarantee coverage of every current or future cheat variant. Keep your IOC set updated.

## Project structure

- `scanner.py` - Main CLI scanner
- `indicators/default_iocs.json` - Starter IOC/rule set

## Requirements

- Windows
- Python 3.10+
- PowerShell in `PATH`

## Quick start

```powershell
python .\scanner.py
```

Default output paths:
- JSON: `%USERPROFILE%\OneDrive\Documents\github\pc-checker\latest_report.json`
- HTML: `%USERPROFILE%\OneDrive\Documents\github\pc-checker\latest_report.html`
- Program anomalies HTML: `%USERPROFILE%\OneDrive\Documents\github\pc-checker\program_anomalies.html`

If OneDrive is unavailable, it falls back to:
- `%USERPROFILE%\Documents\github\pc-checker\...`
- then local `reports\...`

## Custom output location

Use CLI flags:

```powershell
python .\scanner.py --json-out .\reports\case-001.json --html-out .\reports\case-001.html --program-html-out .\reports\case-001-programs.html
```

Or set an environment variable for default output:

```powershell
$env:PC_CHECKER_REPORT_DIR = "D:\forensics\pc-checker"
python .\scanner.py
```

## Common commands

Custom IOC file:

```powershell
python .\scanner.py --ioc .\indicators\my_iocs.json
```

Reduce console output:

```powershell
python .\scanner.py --print-limit 10
```

Fast triage (skip file scan):

```powershell
python .\scanner.py --skip-files
```

Skip unusual/unsigned program anomaly checks:

```powershell
python .\scanner.py --skip-program-anomalies
```

## IOC format overview

Rule arrays supported in `default_iocs.json`:
- `process_rules`
- `program_anomaly_rules`
- `service_rules`
- `registry_rules`
- `file_rules`
- `boot_rules`

Common fields:
- `id`
- `pattern`
- `target_field`
- `mode` (`wildcard`, `regex`, `glob`, `exact`)
- `severity` (`critical|high|medium|low|info`)
- `description`

`program_anomaly_rules` supports:
- Suspicious and trusted path patterns
- Signature status buckets (critical vs unsigned)
- Unusual executable name regexes
- Suspicious command-line regexes
- Custom process rules for anomaly scoring

## Operational tips

- Run from elevated PowerShell for better visibility.
- Version-control IOC changes.
- Manually review detections before enforcement due to possible false positives.
