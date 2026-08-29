#!/usr/bin/env python3
import argparse
import logging
from pathlib import Path

import angr


def one_line(value: object) -> str:
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def ghidra_address(value: str) -> int:
    """Accept plain hex and Ghidra segmented addresses such as ram:00000000."""
    return int(value.rsplit(":", 1)[-1], 16)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_elf")
    parser.add_argument("ghidra_failures_tsv")
    parser.add_argument("output_directory")
    parser.add_argument("ghidra_image_base")
    args = parser.parse_args()

    input_elf = Path(args.input_elf).resolve()
    failures_tsv = Path(args.ghidra_failures_tsv).resolve()
    output_directory = Path(args.output_directory).resolve()
    ghidra_image_base = ghidra_address(args.ghidra_image_base)
    output_directory.mkdir(parents=True, exist_ok=True)

    requested: list[tuple[int, str]] = []
    with failures_tsv.open("r", encoding="utf-8") as source:
        next(source, None)
        for line in source:
            fields = line.rstrip("\n").split("\t", 2)
            if len(fields) >= 2:
                requested.append((ghidra_address(fields[0]), fields[1]))

    logging.getLogger("angr").setLevel(logging.WARNING)
    project = angr.Project(str(input_elf), auto_load_libs=False)
    angr_mapped_base = project.loader.main_object.mapped_base
    target_addresses = [
        address - ghidra_image_base + angr_mapped_base for address, _ in requested
    ]
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        function_starts=target_addresses,
    )

    source_path = output_directory / "angr-decompiled.c"
    status_path = output_directory / "angr-functions.tsv"
    failure_path = output_directory / "angr-failures.tsv"
    summary_path = output_directory / "angr-summary.properties"

    completed = 0
    failed = 0
    with (
        source_path.open("w", encoding="utf-8", newline="\n") as source,
        status_path.open("w", encoding="utf-8", newline="\n") as status,
        failure_path.open("w", encoding="utf-8", newline="\n") as failures,
    ):
        source.write(f"/* angr {angr.__version__}; input: {input_elf.name} */\n\n")
        status.write("ghidra_address\tangr_address\tname\tstatus\n")
        failures.write("ghidra_address\tname\terror\n")
        for ghidra_address, ghidra_name in sorted(requested):
            angr_address = ghidra_address - ghidra_image_base + angr_mapped_base
            function = cfg.kb.functions.get(angr_address)
            if function is None:
                failed += 1
                error = "CFGFast did not identify the requested function address"
                status.write(
                    f"{ghidra_address:x}\t{angr_address:x}\t{one_line(ghidra_name)}\tfailed\n"
                )
                failures.write(f"{ghidra_address:x}\t{one_line(ghidra_name)}\t{error}\n")
                continue
            try:
                result = project.analyses.Decompiler(function, cfg=cfg.model)
                if result.codegen is None or not result.codegen.text.strip():
                    raise RuntimeError("angr returned no decompiler text")
                completed += 1
                status.write(
                    f"{ghidra_address:x}\t{angr_address:x}\t{one_line(ghidra_name)}\tdecompiled\n"
                )
                source.write(
                    f"/* Ghidra {ghidra_address:x}; angr {angr_address:x}; "
                    f"{one_line(ghidra_name)} */\n"
                )
                source.write(result.codegen.text)
                source.write("\n\n")
            except Exception as error:  # Every failure is written to the output artifact.
                failed += 1
                message = one_line(error)
                status.write(
                    f"{ghidra_address:x}\t{angr_address:x}\t{one_line(ghidra_name)}\tfailed\n"
                )
                failures.write(
                    f"{ghidra_address:x}\t{one_line(ghidra_name)}\t{message}\n"
                )

    with summary_path.open("w", encoding="utf-8", newline="\n") as summary:
        summary.write(f"angr_version={angr.__version__}\n")
        summary.write(f"requested={len(requested)}\n")
        summary.write(f"decompiled={completed}\n")
        summary.write(f"failed={failed}\n")

    return 0 if requested and failed == 0 and completed == len(requested) else 1


if __name__ == "__main__":
    raise SystemExit(main())
