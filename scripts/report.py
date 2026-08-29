#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys
from pathlib import Path


root = Path(sys.argv[1]).resolve()
records = []
for target in sorted((root / "binaries").iterdir()):
    if not target.is_dir():
        continue
    build = json.loads((target / "build.json").read_text())
    for key in ("debug", "release", "stripped", "detached_debug"):
        path = target / build[key]
        raw = path.read_bytes()
        description = subprocess.check_output(["file", "-b", str(path)], text=True).strip()
        records.append({
            "target": target.name, "variant": key, "file": str(path.relative_to(root)),
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "description": description
        })
(root / "reports").mkdir(exist_ok=True)
(root / "reports" / "build-report.json").write_text(json.dumps({"artifacts": records}, indent=2) + "\n")

