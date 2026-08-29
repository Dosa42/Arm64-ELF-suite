# Vendor ELF Decompiler Tool

This tool takes the supplied vendor ZIP as its only analysis input, finds every
ELF file by its `7f 45 4c 46` magic bytes, and runs Ghidra headlessly on every
file. Outputs mirror the original `vendor/` paths. The bundled ARC processor
module adds the processor needed for the ARCv2 ELF in the supplied vendor ZIP.
If Ghidra reports a function failure, the launcher records it and tries RetDec,
then angr for the exact failed function addresses.

## Run

```bash
./install_decompiler_dependencies.sh
./decompile_vendor_elfs.sh /path/to/vendor-a32.zip /path/to/output 4
```

Each ELF output directory contains:

- `decompiled.c`: Ghidra C decompiler output for every discovered internal function.
- `disassembly.tsv`: every instruction Ghidra decoded.
- `functions.tsv`: every discovered function and its status.
- `decompilation-failures.tsv`: explicit per-function failures.
- `decompilation-warnings.tsv`: functions whose C output contains nonfatal
  warning comments; these are retained, not silently treated as clean output.
- `retdec.c` or `angr-decompiled.c`: explicit fallback output when required.
- `summary.properties`: exact counts and selected processor language.
- `ghidra.log`, `ghidra-script.log`, and `headless-output.log`: raw tool output.
- `command.txt` and `headless-exit-code.txt`: the executed command and exit status.

At the output root, `elf-manifest.tsv`, `results.tsv`, and
`run-summary.properties` cover the complete batch. Rerunning resumes files with
a matching input SHA-256 and reruns unfinished files.
