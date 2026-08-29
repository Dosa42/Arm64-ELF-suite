#!/usr/bin/env bash
set -euo pipefail

tool_root=$(cd "$(dirname "$0")" && pwd)
download_root="$tool_root/.downloads"
install_root="$tool_root/.tools"

ghidra_url='https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip'
ghidra_sha256='93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54'
jdk_url='https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz'
jdk_sha256='ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94'
retdec_url='https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz'
retdec_sha256='e5a7dd82987ff52b8c714892277d0b1d0190ab778c03036d01eb69c7658ab1a5'

mkdir -p "$download_root" "$install_root"

download_and_verify() {
    url=$1
    destination=$2
    expected=$3
    curl -fL --retry 5 --retry-all-errors --continue-at - -o "$destination" "$url"
    actual=$(sha256sum "$destination" | cut -d ' ' -f 1)
    if [ "$actual" != "$expected" ]; then
        echo "SHA-256 mismatch for $destination" >&2
        echo "Expected: $expected" >&2
        echo "Actual:   $actual" >&2
        exit 1
    fi
}

if [ ! -x "$install_root/ghidra_12.1.3_PUBLIC/support/analyzeHeadless" ]; then
    ghidra_zip="$download_root/ghidra_12.1.3_PUBLIC_20260817.zip"
    download_and_verify "$ghidra_url" "$ghidra_zip" "$ghidra_sha256"
    unzip -q "$ghidra_zip" -d "$install_root"
fi

if [ ! -x "$install_root/jdk21/bin/javac" ]; then
    jdk_archive="$download_root/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz"
    download_and_verify "$jdk_url" "$jdk_archive" "$jdk_sha256"
    mkdir -p "$install_root/jdk21"
    tar -xzf "$jdk_archive" -C "$install_root/jdk21" --strip-components=1
fi

if [ -d "$tool_root/arc_processor/ARC" ]; then
    mkdir -p "$install_root/ghidra_12.1.3_PUBLIC/Ghidra/Processors/ARC"
    cp -a "$tool_root/arc_processor/ARC/." \
        "$install_root/ghidra_12.1.3_PUBLIC/Ghidra/Processors/ARC/"
fi

if [ ! -x "$install_root/retdec-5.0/bin/retdec-decompiler" ]; then
    retdec_archive="$download_root/RetDec-v5.0-Linux-Release.tar.xz"
    download_and_verify "$retdec_url" "$retdec_archive" "$retdec_sha256"
    mkdir -p "$install_root/retdec-5.0"
    tar --no-same-owner -xJf "$retdec_archive" -C "$install_root/retdec-5.0"
fi

if [ ! -x "$install_root/angr-venv/bin/python" ]; then
    python3 -m venv "$install_root/angr-venv"
    "$install_root/angr-venv/bin/python" -m pip install \
        --disable-pip-version-check --no-input \
        -r "$tool_root/requirements-angr.lock"
fi

"$install_root/jdk21/bin/java" -version
"$install_root/jdk21/bin/javac" -version
"$install_root/retdec-5.0/bin/retdec-decompiler" --version
"$install_root/angr-venv/bin/python" -c 'import angr; print("angr", angr.__version__)'
test -x "$install_root/ghidra_12.1.3_PUBLIC/support/analyzeHeadless"
echo "Ghidra analyzeHeadless 12.1.3 installed"
