#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 BINARY OUTPUT_DIR GHIDRA_ROOT" >&2
  exit 2
fi

binary=$(realpath "$1")
output=$2
ghidra_root=$3
mkdir -p "$output/ghidra" "$output/ghidra-project"

file "$binary" > "$output/file.txt"
sha256sum "$binary" > "$output/sha256.txt"
aarch64-linux-gnu-readelf -h "$binary" > "$output/readelf-header.txt"
aarch64-linux-gnu-readelf -lW "$binary" > "$output/readelf-segments.txt"
aarch64-linux-gnu-readelf -SW "$binary" > "$output/readelf-sections.txt"
aarch64-linux-gnu-readelf -dW "$binary" > "$output/readelf-dynamic.txt" 2>&1 || true
aarch64-linux-gnu-readelf -sW "$binary" > "$output/readelf-symbols.txt"
aarch64-linux-gnu-readelf -rW "$binary" > "$output/readelf-relocations.txt" 2>&1 || true
aarch64-linux-gnu-readelf -nW "$binary" > "$output/readelf-notes.txt" 2>&1 || true
aarch64-linux-gnu-objdump -d -S "$binary" > "$output/disassembly.txt"
aarch64-linux-gnu-objdump -p "$binary" > "$output/program-headers.txt"
aarch64-linux-gnu-nm -a -C "$binary" > "$output/symbols-all.txt" 2>&1 || true
aarch64-linux-gnu-nm -D -C "$binary" > "$output/symbols-dynamic.txt" 2>&1 || true
strings -a -t x "$binary" > "$output/strings.txt"

"$ghidra_root/support/analyzeHeadless" \
  "$output/ghidra-project" project \
  -import "$binary" \
  -overwrite \
  -analysisTimeoutPerFile 600 \
  -scriptPath "$(dirname "$0")/ghidra" \
  -postScript ExportDecompiled.java "$output/ghidra" \
  > "$output/ghidra-headless.log" 2>&1

