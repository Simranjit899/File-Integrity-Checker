#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from datetime import datetime

BASELINE_FILE = "baseline.json"
TARGETS_FILE = "targets.txt"
LOG_FILE = "logs/integrity_alerts.log"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_targets(file_path: str) -> list[str]:
    targets = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(os.path.expanduser(line))
    return targets


def write_log(line: str) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def create_baseline() -> None:
    targets = load_targets(TARGETS_FILE)

    baseline = {
        "created_utc": datetime.utcnow().isoformat() + "Z",
        "algorithm": "sha256",
        "files": {},
        "missing": []
    }

    for path in targets:
        try:
            baseline["files"][path] = sha256_file(path)
        except (FileNotFoundError, PermissionError):
            baseline["missing"].append(path)

    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    print(f"[OK] Baseline saved to {BASELINE_FILE}")
    print(f"[OK] Hashed files: {len(baseline['files'])}")
    if baseline["missing"]:
        print(f"[WARN] Skipped (missing/permission): {len(baseline['missing'])}")
        for p in baseline["missing"]:
            print(f"  - {p}")


def check_integrity() -> int:
    if not os.path.exists(BASELINE_FILE):
        print(f"[ERROR] {BASELINE_FILE} not found. Run: python3 fic.py baseline")
        return 2

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    baseline_files: dict = baseline.get("files", {})
    modified = []
    missing = []
    unchanged = 0

    for path, old_hash in baseline_files.items():
        try:
            new_hash = sha256_file(path)
            if new_hash != old_hash:
                modified.append(path)
            else:
                unchanged += 1
        except (FileNotFoundError, PermissionError):
            missing.append(path)

    timestamp = datetime.utcnow().isoformat() + "Z"

    print(f"=== File Integrity Check ({timestamp}) ===")
    print(f"Unchanged: {unchanged}")
    print(f"Modified:  {len(modified)}")
    print(f"Missing:   {len(missing)}")

    # Log alerts (only modified/missing)
    for p in modified:
        line = f"{timestamp} [ALERT] MODIFIED: {p}"
        write_log(line)
        print(line)

    for p in missing:
        line = f"{timestamp} [ALERT] MISSING:  {p}"
        write_log(line)
        print(line)

    if not modified and not missing:
        ok_line = f"{timestamp} [OK] No integrity violations detected."
        write_log(ok_line)
        print(ok_line)

    # exit code: 0=clean, 1=violations
    return 1 if (modified or missing) else 0


def main():
    parser = argparse.ArgumentParser(description="File Integrity Checker (SHA-256)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("baseline", help="Create baseline.json from targets.txt")
    sub.add_parser("check", help="Compare current hashes against baseline.json")

    args = parser.parse_args()

    if args.cmd == "baseline":
        create_baseline()
    elif args.cmd == "check":
        raise SystemExit(check_integrity())


if __name__ == "__main__":
    main()
