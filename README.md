# Arm64 ELF Suite

Builds one C source package into three real AArch64 ELF executables and reverses each result into inspectable analysis artifacts.

## Targets

| Target | Compiler/ABI | Output |
|---|---|---|
| Linux glibc | `aarch64-linux-gnu-gcc` | Dynamically linked GNU/Linux AArch64 ELF |
| Linux musl | Zig `cc -target aarch64-linux-musl` | Fully static GNU/Linux AArch64 ELF |
| Android Bionic | Android NDK Clang `aarch64-linux-android<API>-clang` | Android AArch64 PIE ELF |

Every target produces an unoptimized debug ELF with DWARF, an optimized release ELF, a stripped release ELF, and a detached debug-symbol file. The workflow also exports Ghidra C-like pseudocode, assembly, ELF headers, sections, segments, dynamic dependencies, relocations, symbols, strings, Build IDs, checksums, and a machine-readable report.

## Source inputs

The workflow accepts either:

1. Repository source under `sample/` or another path supplied as `source_path`.
2. A ZIP or TAR archive already committed to the repository, supplied as `archive_path`.
3. A public HTTPS ZIP or TAR URL supplied as `archive_url`.

Only one of `archive_path` and `archive_url` may be set. Archive contents are extracted into a clean staging directory.

## Build contract

Put an `elf-suite.json` file at the root of the selected source package:

```json
{
  "name": "hello-arm64",
  "sources": ["src/main.c"],
  "include_dirs": ["include"],
  "defines": ["ELF_SUITE_BUILD=1"],
  "cflags": ["-Wall", "-Wextra"],
  "ldflags": []
}
```

Paths must remain inside the selected source directory. If the manifest is absent, every `.c` file below the source root is compiled and the executable is named `program`.

## Run the workflow

Open **Actions → Build and Decompile ARM64 ELFs → Run workflow**.

- Repository example: keep `source_path` as `sample`.
- Repository project: set `source_path` to its directory.
- Committed archive: set `archive_path`, for example `inputs/my-source.zip`.
- Public archive: set `archive_url` to its HTTPS URL.
- Android defaults to API 30 and can be changed with `android_api`.

## Artifact layout

```text
arm64-elf-suite/
├── binaries/<target>/
│   ├── <name>-debug
│   ├── <name>-release
│   ├── <name>-release.stripped
│   └── <name>-release.debug
├── analysis/<target>/<variant>/
│   ├── ghidra/*.c
│   ├── disassembly.txt
│   ├── symbols*.txt
│   ├── readelf-*.txt
│   ├── strings.txt
│   └── file.txt
├── reports/build-report.json
└── SHA256SUMS
```

## Decompilation limits

Ghidra recovers C-like pseudocode, not the exact original source. Optimisation, stripping, macros, comments, formatting, and discarded names cannot be perfectly reconstructed. The debug ELF retains DWARF and symbols specifically to provide the strongest reconstruction available.

## Vendor batch: 1,923 ELF files

`Decompile Vendor ELF Batch` handles the complete `vendor-a32.zip` population through deterministic parallel shards. A full workflow run is successful only when all 1,923 ELF inputs produce a non-empty UTF-8 plain-text C file.

The final success artifact is named `vendor-a32-1923-fully-decompiled-plain-c`. Its `plain-c/` tree mirrors the original vendor paths and appends `.c`, for example `vendor/lib64/libexample.so.c`. Logs, disassembly, partial outputs, or an unresolved function never satisfy the final success gate.

