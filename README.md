# File Integrity Checker (SHA-256) — Linux

A lightweight File Integrity Checker (FIC) built in Python to detect **unauthorized file changes** by comparing current file hashes against a trusted baseline.

This project demonstrates host-based monitoring fundamentals used in security operations, incident response, and hardening workflows.

---

## Why this project
Attackers often modify files quietly (configs, system files, scripts) to maintain access or weaken security.  
A file integrity checker helps detect:
- **Modified files**
- **Missing/deleted files**
- Change evidence (hash + metadata)

---

## Features
- **Baseline creation** (trusted state) using SHA-256
- **Integrity checks** against baseline
- Detects:
  - ✅ Unchanged files
  - 🚨 Modified files (hash mismatch)
  - ❌ Missing files
- **Report output** (`reports/last_check_report.json`)
- **Alert logging** (`logs/integrity_alerts.log`)
- **Automation-ready** via cron (Phase-3)

---

## Tech stack
- Python 3
- hashlib, json, os (standard library)
- Linux (Ubuntu)
- cron (optional automation)

---

## Project Structure
```text
File-Integrity-Checker/
├── fic.py
├── targets.txt
├── baseline.json
├── reports/
│   └── last_check_report.json
├── screenshots/
├── logs/                  # local only (not pushed)
└── README.md
