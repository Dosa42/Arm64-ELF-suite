#!/usr/bin/env python3
import argparse
import hashlib
import json
import shutil
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected", required=True, type=int)
    args = parser.parse_args()
    plain_root = args.output / "plain-c"
    plain_root.mkdir(parents=True, exist_ok=True)
    records = []
    seen = set()

    for shard in sorted(args.input.glob("vendor-decompiled-shard-*")):
        index_path = shard / "plain-c-index.json"
        if not index_path.exists():
            raise SystemExit(f"missing plain C index: {shard}")
        index = json.loads(index_path.read_text())
        if index["unresolved"] or index["plain_c_complete"] != index["selected"]:
            raise SystemExit(f"shard is not fully decompiled: {shard}")
        for row in index["files"]:
            elf_path = row["elf"]
            if elf_path in seen:
                raise SystemExit(f"duplicate ELF result: {elf_path}")
            seen.add(elf_path)
            source = shard / row["c_file"]
            if not source.is_file() or source.stat().st_size == 0:
                raise SystemExit(f"missing or empty C file: {source}")
            source.read_text(encoding="utf-8")
            destination = plain_root / Path(elf_path + ".c")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            records.append({
                "elf": elf_path,
                "c_file": str(destination.relative_to(args.output)),
                "bytes": destination.stat().st_size,
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                "source": row["source"],
                "status": "fully_decompiled_plain_c",
            })

    records.sort(key=lambda item: item["elf"])
    if len(records) != args.expected:
        raise SystemExit(f"expected {args.expected} plain C files, found {len(records)}")
    report = {"expected_elf": args.expected, "plain_c_files": len(records), "unresolved": 0, "files": records}
    (args.output / "plain-c-index.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
