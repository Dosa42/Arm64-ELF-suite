#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 CHECKPOINT_ARCHIVE OUTPUT_DIRECTORY" >&2
  exit 2
fi
archive=$1
output=$2
mkdir -p "$output"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
tar -xzf "$archive" -C "$staging"
root=$(find "$staging" -mindepth 1 -maxdepth 1 -type d | head -n1)
test -n "$root"
cp -a "$root/." "$output/"

