#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


def contained(root: Path, value: str) -> Path:
    result = (root / value).resolve()
    if root.resolve() not in result.parents and result != root.resolve():
        raise ValueError(f"path escapes source root: {value}")
    return result


def load_manifest(source: Path) -> dict:
    path = source / "elf-suite.json"
    if path.exists():
        data = json.loads(path.read_text())
    else:
        data = {
            "name": "program",
            "sources": [str(path.relative_to(source)) for path in sorted(source.rglob("*.c"))],
            "include_dirs": [], "defines": [], "cflags": [], "ldflags": []
        }
    name = data.get("name", "")
    if not name or not all(ch.isalnum() or ch in "-_" for ch in name):
        raise ValueError("manifest name may contain only letters, digits, '-' and '_'")
    if not data.get("sources"):
        raise ValueError("manifest contains no source files")
    return data


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def compiler_for(target: str, android_api: int) -> tuple[list[str], list[str]]:
    if target == "linux-glibc":
        return ["aarch64-linux-gnu-gcc"], []
    if target == "linux-musl-static":
        return ["zig", "cc", "-target", "aarch64-linux-musl"], ["-static", "-D__MUSL__=1"]
    if target == "android-bionic":
        ndk = Path(os.environ["ANDROID_NDK_HOME"])
        host = "linux-x86_64"
        compiler = ndk / "toolchains/llvm/prebuilt" / host / "bin" / f"aarch64-linux-android{android_api}-clang"
        if not compiler.exists():
            raise FileNotFoundError(compiler)
        return [str(compiler)], ["-fPIE", "-pie"]
    raise ValueError(target)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=["linux-glibc", "linux-musl-static", "android-bionic"])
    parser.add_argument("--android-api", type=int, default=30)
    args = parser.parse_args()
    source = args.source.resolve()
    manifest = load_manifest(source)
    cc, target_flags = compiler_for(args.target, args.android_api)

    sources = [str(contained(source, item)) for item in manifest["sources"]]
    includes = [f"-I{contained(source, item)}" for item in manifest.get("include_dirs", [])]
    defines = [f"-D{item}" for item in manifest.get("defines", [])]
    common = includes + defines + manifest.get("cflags", []) + target_flags
    args.output.mkdir(parents=True, exist_ok=True)
    name = manifest["name"]
    debug = args.output / f"{name}-debug"
    release = args.output / f"{name}-release"
    stripped = args.output / f"{name}-release.stripped"
    detached = args.output / f"{name}-release.debug"

    run(cc + common + ["-O0", "-g3", "-fno-omit-frame-pointer"] + sources + manifest.get("ldflags", []) + ["-o", str(debug)])
    run(cc + common + ["-O2", "-g", "-fno-omit-frame-pointer"] + sources + manifest.get("ldflags", []) + ["-o", str(release)])
    shutil.copy2(release, stripped)
    objcopy = "aarch64-linux-gnu-objcopy"
    run([objcopy, "--only-keep-debug", str(release), str(detached)])
    run([objcopy, "--strip-debug", "--strip-unneeded", str(stripped)])
    run([objcopy, f"--add-gnu-debuglink={detached}", str(stripped)])

    metadata = {
        "target": args.target, "name": name, "compiler": cc,
        "debug": debug.name, "release": release.name,
        "stripped": stripped.name, "detached_debug": detached.name,
    }
    (args.output / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()

