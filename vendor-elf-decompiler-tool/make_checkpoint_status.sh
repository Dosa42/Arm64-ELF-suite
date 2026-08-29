#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <decompiler-output-directory>" >&2
    exit 2
fi

output_root=$(readlink -f "$1")
manifest="$output_root/elf-manifest.tsv"
results="$output_root/checkpoint-results.tsv"
summary_out="$output_root/checkpoint-summary.properties"

if [ ! -f "$manifest" ]; then
    echo "ELF manifest not found: $manifest" >&2
    exit 2
fi

printf 'path\tstatus\tinput_sha256\ttool_version\tfunctions_total\tfunctions_decompiled\tfunctions_external\tfunctions_failed\tfunctions_with_warnings\tinstructions\n' > "$results"

total=0
complete_primary=0
complete_fallback=0
failed=0
interrupted=0
not_started=0

while IFS=$'\t' read -r relative_path size input_sha elf_class machine description; do
    [ "$relative_path" != path ] || continue
    total=$((total + 1))
    destination="$output_root/decompiled/$relative_path"
    batch_status=""
    [ -f "$destination/batch-status.txt" ] && \
        batch_status=$(tr -d '\r\n' < "$destination/batch-status.txt")

    case "$batch_status" in
        complete)
            status=complete_primary
            complete_primary=$((complete_primary + 1))
            ;;
        complete_with_fallback)
            status=complete_fallback
            complete_fallback=$((complete_fallback + 1))
            ;;
        failed)
            status=failed
            failed=$((failed + 1))
            ;;
        *)
            if [ -f "$destination/command.txt" ]; then
                status=interrupted_in_progress
                interrupted=$((interrupted + 1))
            else
                status=not_started
                not_started=$((not_started + 1))
            fi
            ;;
    esac

    properties="$destination/summary.properties"
    tool_version=""
    functions_total=""
    functions_decompiled=""
    functions_external=""
    functions_failed=""
    functions_with_warnings=""
    instructions=""
    if [ -f "$properties" ]; then
        tool_version=$(sed -n 's/^tool_version=//p' "$properties" | head -n 1)
        functions_total=$(sed -n 's/^functions_total=//p' "$properties" | head -n 1)
        functions_decompiled=$(sed -n 's/^functions_decompiled=//p' "$properties" | head -n 1)
        functions_external=$(sed -n 's/^functions_external=//p' "$properties" | head -n 1)
        functions_failed=$(sed -n 's/^functions_failed=//p' "$properties" | head -n 1)
        functions_with_warnings=$(sed -n 's/^functions_with_warnings=//p' "$properties" | head -n 1)
        instructions=$(sed -n 's/^instructions=//p' "$properties" | head -n 1)
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$relative_path" "$status" "$input_sha" "$tool_version" \
        "$functions_total" "$functions_decompiled" "$functions_external" \
        "$functions_failed" "$functions_with_warnings" "$instructions" >> "$results"
done < "$manifest"

{
    printf 'elf_total=%s\n' "$total"
    printf 'complete_primary=%s\n' "$complete_primary"
    printf 'complete_fallback=%s\n' "$complete_fallback"
    printf 'failed=%s\n' "$failed"
    printf 'interrupted_in_progress=%s\n' "$interrupted"
    printf 'not_started=%s\n' "$not_started"
    printf 'paused=true\n'
} > "$summary_out"

cat "$summary_out"
