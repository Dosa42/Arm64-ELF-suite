#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 HTTPS_URL DESTINATION EXPECTED_SHA256" >&2
  exit 2
fi
url=$1
destination=$2
expected=$3
case "$url" in https://*) ;; *) echo "input URL must use HTTPS" >&2; exit 2;; esac
mkdir -p "$(dirname "$destination")"
curl --fail --location --retry 8 --retry-all-errors --continue-at - --output "$destination" "$url"
actual=$(sha256sum "$destination" | cut -d ' ' -f1)
if [ -n "$expected" ] && [ "$actual" != "$expected" ]; then
  echo "input SHA-256 mismatch: expected=$expected actual=$actual" >&2
  exit 1
fi
printf '%s  %s\n' "$actual" "$destination"

