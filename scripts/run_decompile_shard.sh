#!/usr/bin/env bash
set -uo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VENDOR_ZIP OUTPUT_DIRECTORY PARALLEL_JOBS" >&2
  exit 2
fi
/opt/vendor-elf-decompiler-tool/decompile_vendor_elfs.sh "$1" "$2" "$3"
tool_status=$?
python3 scripts/emit_plain_c.py --output "$2"
plain_c_status=$?
if [ "$tool_status" -ne 0 ] || [ "$plain_c_status" -ne 0 ]; then
  exit 1
fi

