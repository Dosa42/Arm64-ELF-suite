#!/usr/bin/env bash
set -uo pipefail

export LC_ALL=C
export TZ=UTC
umask 022

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <vendor.zip> <output-directory> [parallel-jobs]" >&2
    exit 2
fi

input_zip=$(readlink -f "$1")
output_root=$(mkdir -p "$2" && readlink -f "$2")
parallel_jobs=${3:-4}
tool_version=9
tool_root=$(cd "$(dirname "$0")" && pwd)
work_root="$output_root/.work"
extract_root="$work_root/extracted"
project_root="$output_root/ghidra-projects"
script_path="$tool_root/ghidra_scripts"

ghidra_home=${GHIDRA_HOME:-"$tool_root/.tools/ghidra_12.1.3_PUBLIC"}
java_home=${JAVA_HOME:-"$tool_root/.tools/jdk21"}
analyze_headless="$ghidra_home/support/analyzeHeadless"
retdec_home=${RETDEC_HOME:-"$tool_root/.tools/retdec-5.0"}
angr_python=${ANGR_PYTHON:-"$tool_root/.tools/angr-venv/bin/python"}

if [ ! -f "$input_zip" ]; then
    echo "Input ZIP does not exist: $input_zip" >&2
    exit 2
fi
if ! [[ "$parallel_jobs" =~ ^[1-9][0-9]*$ ]]; then
    echo "parallel-jobs must be a positive integer" >&2
    exit 2
fi
if [ ! -x "$analyze_headless" ]; then
    echo "Ghidra not found at $ghidra_home" >&2
    echo "Run install_decompiler_dependencies.sh or set GHIDRA_HOME." >&2
    exit 2
fi
if [ ! -x "$java_home/bin/java" ] || [ ! -x "$java_home/bin/javac" ]; then
    echo "Java 21 JDK not found at $java_home" >&2
    echo "Run install_decompiler_dependencies.sh or set JAVA_HOME." >&2
    exit 2
fi

export JAVA_HOME="$java_home"
export PATH="$JAVA_HOME/bin:$PATH"

mkdir -p "$extract_root" "$project_root" "$output_root/decompiled" "$output_root/logs"

if [ ! -f "$extract_root/.extraction-complete" ]; then
    unzip -t "$input_zip" > "$output_root/logs/zip-test.log"
    unzip -q "$input_zip" -d "$extract_root"
    sha256sum "$input_zip" > "$extract_root/.extraction-complete"
fi

vendor_root="$extract_root/vendor"
if [ ! -d "$vendor_root" ]; then
    echo "The ZIP did not produce a vendor/ directory" >&2
    exit 1
fi

all_elf_list="$output_root/elf-files-all.nul"
: > "$all_elf_list"
while IFS= read -r -d '' candidate; do
    magic=$(dd if="$candidate" bs=4 count=1 status=none | od -An -tx1 | tr -d ' \n')
    if [ "$magic" = "7f454c46" ]; then
        printf '%s\0' "$candidate" >> "$all_elf_list"
    fi
done < <(find "$vendor_root" -type f -print0 | sort -z)

elf_total=$(tr -cd '\0' < "$all_elf_list" | wc -c)
printf '%s\n' "$elf_total" > "$output_root/elf-count-global.txt"
if [ -n "${EXPECTED_ELF_COUNT:-}" ] && [ "$elf_total" -ne "$EXPECTED_ELF_COUNT" ]; then
    echo "Expected $EXPECTED_ELF_COUNT ELF files, found $elf_total" >&2
    exit 1
fi

shard_index=${ELF_SHARD_INDEX:-0}
shard_count=${ELF_SHARD_COUNT:-1}
if ! [[ "$shard_index" =~ ^[0-9]+$ ]] || ! [[ "$shard_count" =~ ^[1-9][0-9]*$ ]] || [ "$shard_index" -ge "$shard_count" ]; then
    echo "Invalid ELF shard index/count: $shard_index/$shard_count" >&2
    exit 2
fi
elf_list="$output_root/elf-files.nul"
python3 - "$all_elf_list" "$elf_list" "$shard_index" "$shard_count" <<'PY'
import sys
from pathlib import Path
source, destination, shard_index, shard_count = sys.argv[1:]
items = [item for item in Path(source).read_bytes().split(b"\0") if item]
selected = [item for index, item in enumerate(items) if index % int(shard_count) == int(shard_index)]
Path(destination).write_bytes(b"\0".join(selected) + (b"\0" if selected else b""))
PY
elf_count=$(tr -cd '\0' < "$elf_list" | wc -c)
printf '%s\n' "$elf_count" > "$output_root/elf-count.txt"
printf 'shard_index=%s\nshard_count=%s\nelf_global=%s\nelf_selected=%s\n' \
    "$shard_index" "$shard_count" "$elf_total" "$elf_count" > "$output_root/shard.properties"

manifest="$output_root/elf-manifest.tsv"
printf 'path\tsize\tsha256\tclass\tmachine\tfile_description\n' > "$manifest"
while IFS= read -r -d '' elf; do
    relative_path=${elf#"$extract_root/"}
    size=$(stat -c '%s' -- "$elf")
    sha256=$(sha256sum -- "$elf" | cut -d ' ' -f 1)
    elf_class=$(readelf -h -- "$elf" 2>/dev/null | sed -n 's/^  Class:[[:space:]]*//p' | head -n 1)
    machine=$(readelf -h -- "$elf" 2>/dev/null | sed -n 's/^  Machine:[[:space:]]*//p' | head -n 1)
    description=$(file -b -- "$elf" | tr '\t\r\n' '   ')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$relative_path" "$size" "$sha256" "$elf_class" "$machine" "$description" >> "$manifest"
done < "$elf_list"

process_one() {
    elf=$1
    relative_path=${elf#"$extract_root/"}
    destination="$output_root/decompiled/$relative_path"
    mkdir -p "$destination"

    # Serialize retries of the same ELF. If a parent launcher is interrupted,
    # any surviving worker holds this lock until it actually exits, preventing
    # a later retry from writing into the same destination concurrently.
    exec 9>"$destination/.worker.lock"
    flock 9

    sha256=$(sha256sum -- "$elf" | cut -d ' ' -f 1)
    expected_complete=$(printf '%s\t%s' "$sha256" "$tool_version")
    if [ -f "$destination/.complete" ] && [ "$(tr -d '\r\n' < "$destination/.complete")" = "$expected_complete" ]; then
        printf 'complete\n' > "$destination/batch-status.txt"
        printf '[RESUME] %s\n' "$relative_path"
        return 0
    fi

    printf '[START] %s\n' "$relative_path"

    if [ -e "$destination/headless-output.log" ] || \
        [ -e "$destination/summary.properties" ] || \
        [ -e "$destination/batch-status.txt" ]; then
        attempts_root="$destination/attempts"
        mkdir -p "$attempts_root"
        attempt_number=$(( $(find "$attempts_root" -mindepth 1 -maxdepth 1 -type d | wc -l) + 1 ))
        attempt_directory=$(printf '%s/%04d' "$attempts_root" "$attempt_number")
        mkdir -p "$attempt_directory"
        for previous in command.txt ghidra.log ghidra-script.log headless-output.log \
            headless-exit-code.txt batch-status.txt summary.properties \
            decompilation-failures.tsv decompilation-warnings.tsv \
            decompiled.c functions.tsv disassembly.tsv .complete \
            retdec.c retdec.log retdec-exit-code.txt angr.log angr-exit-code.txt \
            angr-decompiled.c angr-functions.tsv angr-failures.tsv angr-summary.properties \
            fallback-backend.txt; do
            if [ -e "$destination/$previous" ]; then
                mv "$destination/$previous" "$attempt_directory/$previous"
            fi
        done
    fi

    path_id=$(printf '%s' "$relative_path" | sha256sum | cut -d ' ' -f 1)
    one_project_root="$project_root/v$tool_version/$path_id"
    # The project is disposable and unique to this ELF. Interrupted Ghidra runs
    # can leave a directory without a .gpr marker, so clear only this exact
    # generated project before retrying.
    if [ -d "$one_project_root" ]; then
        find "$one_project_root" -mindepth 1 -delete
    fi
    mkdir -p "$one_project_root"

    printf '%q ' "$analyze_headless" "$one_project_root" program \
        -import "$elf" -scriptPath "$script_path" \
        -postScript DecompileAllFunctions.java "$destination" "$sha256" "$relative_path" "$tool_version" \
        -max-cpu 1 -deleteProject -log "$destination/ghidra.log" \
        -scriptlog "$destination/ghidra-script.log" \
        > "$destination/command.txt"
    printf '\n' >> "$destination/command.txt"

    "$analyze_headless" "$one_project_root" program \
        -import "$elf" \
        -scriptPath "$script_path" \
        -postScript DecompileAllFunctions.java "$destination" "$sha256" "$relative_path" "$tool_version" \
        -max-cpu 1 \
        -deleteProject \
        -log "$destination/ghidra.log" \
        -scriptlog "$destination/ghidra-script.log" \
        > "$destination/headless-output.log" 2>&1
    command_status=$?
    printf '%s\n' "$command_status" > "$destination/headless-exit-code.txt"

    current_complete=""
    if [ -f "$destination/.complete" ]; then
        current_complete=$(tr -d '\r\n' < "$destination/.complete")
    fi
    if [ "$command_status" -eq 0 ] && [ "$current_complete" = "$expected_complete" ]; then
        printf 'complete\n' > "$destination/batch-status.txt"
        printf '[DONE] %s\n' "$relative_path"
        return 0
    fi

    fallback_complete=false
    if [ -x "$retdec_home/bin/retdec-decompiler" ]; then
        "$retdec_home/bin/retdec-decompiler" --keep-unreachable-funcs \
            --backend-no-time-varying-info --output "$destination/retdec.c" "$elf" \
            > "$destination/retdec.log" 2>&1
        retdec_status=$?
        printf '%s\n' "$retdec_status" > "$destination/retdec-exit-code.txt"
        if [ "$retdec_status" -eq 0 ] && [ -s "$destination/retdec.c" ]; then
            fallback_complete=true
            printf 'retdec\n' > "$destination/fallback-backend.txt"
        fi
    fi

    if [ "$fallback_complete" != true ] && [ -x "$angr_python" ] && \
        [ -s "$destination/decompilation-failures.tsv" ]; then
        ghidra_image_base=$(sed -n 's/^image_base=//p' "$destination/summary.properties" | head -n 1)
        [ -n "$ghidra_image_base" ] || ghidra_image_base=0
        "$angr_python" "$tool_root/angr_decompile_failures.py" \
            "$elf" "$destination/decompilation-failures.tsv" "$destination" "$ghidra_image_base" \
            > "$destination/angr.log" 2>&1
        angr_status=$?
        printf '%s\n' "$angr_status" > "$destination/angr-exit-code.txt"
        if [ "$angr_status" -eq 0 ] && [ -s "$destination/angr-decompiled.c" ]; then
            fallback_complete=true
            printf 'angr\n' > "$destination/fallback-backend.txt"
        fi
    fi

    if [ "$fallback_complete" = true ]; then
        printf '%s\n' "$expected_complete" > "$destination/.complete"
        printf 'complete_with_fallback\n' > "$destination/batch-status.txt"
        printf '[DONE-FALLBACK] %s\n' "$relative_path"
    else
        printf 'failed\n' > "$destination/batch-status.txt"
        printf '[FAILED] %s (Ghidra exit %s; see %s)\n' \
            "$relative_path" "$command_status" "$destination/headless-output.log"
    fi
    return 0
}

export -f process_one
export extract_root output_root project_root analyze_headless script_path tool_version
export retdec_home angr_python tool_root

xargs -0 -r -n 1 -P "$parallel_jobs" bash -c 'process_one "$1"' _ < "$elf_list"

results="$output_root/results.tsv"
printf 'path\tstatus\tfunctions_total\tfunctions_decompiled\tfunctions_external\tfunctions_failed\tfunctions_with_warnings\tinstructions\n' > "$results"
complete_count=0
failed_count=0
while IFS= read -r -d '' elf; do
    relative_path=${elf#"$extract_root/"}
    destination="$output_root/decompiled/$relative_path"
    status=failed
    [ -f "$destination/batch-status.txt" ] && status=$(tr -d '\r\n' < "$destination/batch-status.txt")
    summary="$destination/summary.properties"
    functions_total=0
    functions_decompiled=0
    functions_external=0
    functions_failed=0
    functions_with_warnings=0
    instructions=0
    if [ -f "$summary" ]; then
        functions_total=$(sed -n 's/^functions_total=//p' "$summary")
        functions_decompiled=$(sed -n 's/^functions_decompiled=//p' "$summary")
        functions_external=$(sed -n 's/^functions_external=//p' "$summary")
        functions_failed=$(sed -n 's/^functions_failed=//p' "$summary")
        functions_with_warnings=$(sed -n 's/^functions_with_warnings=//p' "$summary")
        instructions=$(sed -n 's/^instructions=//p' "$summary")
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$relative_path" "$status" "$functions_total" "$functions_decompiled" \
        "$functions_external" "$functions_failed" "$functions_with_warnings" \
        "$instructions" >> "$results"
    if [ "$status" = complete ] || [ "$status" = complete_with_fallback ]; then
        complete_count=$((complete_count + 1))
    else
        failed_count=$((failed_count + 1))
    fi
done < "$elf_list"

{
    printf 'input_zip=%s\n' "$input_zip"
    printf 'elf_total_global=%s\n' "$elf_total"
    printf 'elf_total_shard=%s\n' "$elf_count"
    printf 'shard_index=%s\n' "$shard_index"
    printf 'shard_count=%s\n' "$shard_count"
    printf 'complete=%s\n' "$complete_count"
    printf 'failed=%s\n' "$failed_count"
    printf 'ghidra_version=12.1.3\n'
    printf 'java_version=%s\n' "$("$JAVA_HOME/bin/java" -version 2>&1 | head -n 1)"
} > "$output_root/run-summary.properties"

printf 'ELF global: %s\nELF shard: %s\nComplete: %s\nFailed: %s\n' "$elf_total" "$elf_count" "$complete_count" "$failed_count"
[ "$failed_count" -eq 0 ]
