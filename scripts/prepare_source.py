#!/usr/bin/env python3
import argparse
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path


def ensure_inside(root: Path, candidate: Path) -> None:
    root = root.resolve()
    candidate = candidate.resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"archive member escapes extraction root: {candidate}")


def extract(archive: Path, destination: Path) -> None:
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as handle:
            for item in handle.infolist():
                ensure_inside(destination, destination / item.filename)
            handle.extractall(destination)
        return
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive, "r:*") as handle:
            for item in handle.getmembers():
                ensure_inside(destination, destination / item.name)
                if item.issym() or item.islnk():
                    raise ValueError(f"archive links are not accepted: {item.name}")
            handle.extractall(destination, filter="data")
        return
    raise ValueError("archive must be ZIP, tar, tar.gz, tar.xz, or tar.bz2")


def collapse_single_directory(root: Path) -> Path:
    entries = list(root.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--source-path", default="sample")
    parser.add_argument("--archive-path", default="")
    parser.add_argument("--archive-url", default="")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if args.archive_path and args.archive_url:
        raise SystemExit("set only one of --archive-path or --archive-url")

    args.output.mkdir(parents=True, exist_ok=False)
    if args.archive_path or args.archive_url:
        with tempfile.TemporaryDirectory() as temp:
            downloaded = Path(temp) / "source.archive"
            archive = downloaded
            if args.archive_url:
                if not args.archive_url.startswith("https://"):
                    raise SystemExit("archive URL must use HTTPS")
                with urllib.request.urlopen(args.archive_url, timeout=120) as response:
                    downloaded.write_bytes(response.read())
            else:
                archive = (args.repository / args.archive_path).resolve()
                ensure_inside(args.repository, archive)
                if not archive.is_file():
                    raise SystemExit(f"archive not found: {archive}")
            staging = Path(temp) / "extracted"
            staging.mkdir()
            extract(archive, staging)
            source = collapse_single_directory(staging)
            shutil.copytree(source, args.output, dirs_exist_ok=True)
    else:
        source = (args.repository / args.source_path).resolve()
        ensure_inside(args.repository, source)
        if not source.is_dir():
            raise SystemExit(f"source directory not found: {source}")
        shutil.copytree(source, args.output, dirs_exist_ok=True)


if __name__ == "__main__":
    main()

