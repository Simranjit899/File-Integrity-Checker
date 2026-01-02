#!/usr/bin/env python3
import hashlib
import json
import os
from datetime import datetime

BASELINE_FILE = "baseline.json"
TARGETS_FILE = "targets.txt"


def sha256_file(path: str) -> str:
    """Return SHA-256 hash of a file (hex)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_targets(file_path: str) -> list[str]:
    """Load target file paths from targets.txt (ignore blanks/comments)."""
    targets = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(os.path.expanduser(line))
    return targets


def create_baseline():
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
        except FileNotFoundError:
            baseline["missing"].append(path)
        except PermissionError:
            baseline["missing"].append(path)

    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    print(f"[OK] Baseline saved to {BASELINE_FILE}")
    print(f"[OK] Hashed files: {len(baseline['files'])}")
    if baseline["missing"]:
        print(f"[WARN] Skipped (missing/permission): {len(baseline['missing'])}")
        for p in baseline["missing"]:
            print(f"  - {p}")


if __name__ == "__main__":
    create_baseline()
