#!/usr/bin/env python3
import argparse
import json
import shutil
from pathlib import Path


def properties(path: Path) -> dict[str, str]:
    values = {}
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
    return values


def nonempty_text(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        path.read_text(encoding="utf-8")
        return True
    except UnicodeDecodeError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.output.resolve()
    extract_root = root / ".work" / "extracted"
    selected = [Path(item.decode()) for item in (root / "elf-files.nul").read_bytes().split(b"\0") if item]
    plain_root = root / "plain-c"
    plain_root.mkdir(parents=True, exist_ok=True)
    records = []
    unresolved = []

    for elf in selected:
        relative = elf.relative_to(extract_root)
        result = root / "decompiled" / relative
        summary = properties(result / "summary.properties")
        status = (result / "batch-status.txt").read_text(errors="replace").strip() if (result / "batch-status.txt").exists() else "missing"
        fallback = (result / "fallback-backend.txt").read_text().strip() if (result / "fallback-backend.txt").exists() else ""
        destination = plain_root / Path(str(relative) + ".c")
        destination.parent.mkdir(parents=True, exist_ok=True)
        source_kind = ""
        valid = False

        if status == "complete" and summary.get("functions_failed", "0") == "0" and nonempty_text(result / "decompiled.c"):
            shutil.copy2(result / "decompiled.c", destination)
            source_kind = "ghidra_all_functions"
            valid = True
        elif status == "complete_with_fallback" and fallback == "retdec" and nonempty_text(result / "retdec.c"):
            shutil.copy2(result / "retdec.c", destination)
            source_kind = "retdec_full_file"
            valid = True
        elif status == "complete_with_fallback" and fallback == "angr":
            angr = properties(result / "angr-summary.properties")
            requested = int(angr.get("requested", "0"))
            decompiled = int(angr.get("decompiled", "0"))
            failed = int(angr.get("failed", "1"))
            if requested > 0 and decompiled == requested and failed == 0 and nonempty_text(result / "decompiled.c") and nonempty_text(result / "angr-decompiled.c"):
                destination.write_text(
                    result.joinpath("decompiled.c").read_text() +
                    "\n\n/* Functions recovered by the angr fallback */\n\n" +
                    result.joinpath("angr-decompiled.c").read_text(),
                    encoding="utf-8",
                )
                source_kind = "ghidra_plus_angr_all_failures"
                valid = True

        record = {
            "elf": str(relative),
            "c_file": str(destination.relative_to(root)) if valid else "",
            "status": "fully_decompiled_plain_c" if valid else "unresolved",
            "source": source_kind,
            "functions_total": summary.get("functions_total", ""),
            "functions_failed_primary": summary.get("functions_failed", ""),
        }
        records.append(record)
        if not valid:
            unresolved.append(str(relative))

    index = {"selected": len(selected), "plain_c_complete": len(selected) - len(unresolved), "unresolved": unresolved, "files": records}
    (root / "plain-c-index.json").write_text(json.dumps(index, indent=2) + "\n")
    if unresolved:
        raise SystemExit(f"{len(unresolved)} ELF files do not have fully recovered plain C output")


if __name__ == "__main__":
    main()

