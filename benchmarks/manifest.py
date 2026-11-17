"""Record observed benchmark environment; recording is not pinning or attestation."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def command(args: list[str]) -> dict:
    try:
        proc = subprocess.run(args, capture_output=True, timeout=10, check=False)
        return {
            "returncode": proc.returncode,
            "output": (proc.stdout + proc.stderr).decode(errors="replace")[:65536],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}


def tree_manifest(root: Path, exclude: tuple[str, ...] = ()) -> dict:
    """Hash actual input bytes, including dirty/untracked files, not just HEAD."""
    result = {}
    for path in sorted(root.rglob("*")):
        if any(part in {".git", "__pycache__", *exclude} for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            result[str(path.relative_to(root))] = {"symlink": os.readlink(path)}
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result[str(path.relative_to(root))] = {"sha256": digest.hexdigest()}
    return result


def collect(root: Path, corpora: Path, base: Path) -> dict:
    files = {}
    for path in sorted((root / "fstec_lint").rglob("*")):
        if path.is_file() and path.suffix in {".py", ".yaml"}:
            files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    dependencies = {}
    for package in ("PyYAML", "Jinja2", "pytest"):
        try:
            dependencies[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            dependencies[package] = None
    return {
        "schema_version": 1,
        "python": sys.version,
        "platform": platform.platform(),
        "os_release": Path("/etc/os-release").read_text()
        if Path("/etc/os-release").exists()
        else None,
        "dependencies": dependencies,
        "candidate_files_sha256": files,
        "harness_input_files": tree_manifest(
            root / "benchmarks", exclude=("results", "outputs", ".corpora")
        ),
        "corpora": {
            p.name: {
                "head": command(["git", "-C", str(p), "rev-parse", "HEAD"]),
                "status": command(
                    ["git", "-C", str(p), "status", "--porcelain", "--untracked-files=all"]
                ),
                "input_files": tree_manifest(p),
            }
            for p in corpora.iterdir()
            if p.is_dir() and (p / ".git").exists()
        },
        "base_rsyslog_sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
        "tools": {
            name: {"path": shutil.which(name), "version": command([name, flag])}
            for name, flag in [("sshd", "-V"), ("rsyslogd", "-v"), ("bash", "--version")]
        },
        "declared_image_digest": os.environ.get("FSTEC_BENCHMARK_IMAGE_DIGEST"),
        "limitations": [
            "Image digest must be supplied and checked against docker inspect outside container",
            "Manifest records observed environment, not proof of isolation or provenance",
        ],
    }


if __name__ == "__main__":
    json.dump(
        collect(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])), sys.stdout, indent=2
    )
    print()
