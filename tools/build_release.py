"""Build updater-compatible ZIP/SHA256 assets from committed Git files only."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile


def build_archive(files: dict[str, bytes], version: str) -> bytes:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Release version must be X.Y.Z")
    manifest = {}
    seen = set()
    for name, content in files.items():
        path = PurePosixPath(name)
        if (
            not name
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in name
            or ":" in name
            or str(path) != name
            or name.casefold() in seen
            or name == "release-manifest.json"
        ):
            raise ValueError("Unsafe or duplicate release path")
        if any(
            part.casefold() in {".git", ".venv", "result", "__pycache__"}
            for part in path.parts
        ):
            raise ValueError("Runtime/private files cannot be released")
        if path.name.casefold() == "known_hosts" or re.fullmatch(
            r"deployment(?:[.-].*)?\.json", path.name, re.IGNORECASE
        ):
            raise ValueError("Deployment state cannot be released")
        seen.add(name.casefold())
        manifest[name] = hashlib.sha256(content).hexdigest()
    required = {
        "run.cmd",
        "run.sh",
        "bootstrap.py",
        "pyproject.toml",
        "cdn_xhttp/__init__.py",
    }
    if not required.issubset(files):
        raise ValueError("Release is missing its launchers or metadata")
    if not re.search(
        rb'^version\s*=\s*"' + re.escape(version.encode()) + rb'"\s*$',
        files["pyproject.toml"],
        re.M,
    ):
        raise ValueError("Release version differs from pyproject.toml")
    if not re.search(
        rb'^__version__\s*=\s*"' + re.escape(version.encode()) + rb'"\s*$',
        files["cdn_xhttp/__init__.py"],
        re.M,
    ):
        raise ValueError("Release version differs from package metadata")
    contents = dict(files)
    contents["release-manifest.json"] = (
        json.dumps({"version": version, "files": manifest}, sort_keys=True, indent=2)
        + "\n"
    ).encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(contents.items()):
            info = zipfile.ZipInfo(f"cdn-xhttp-setup-{version}/{name}")
            info.create_system = 3
            info.external_attr = (0o100755 if name == "run.sh" else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    return buffer.getvalue()


def committed_files(root: Path) -> dict[str, bytes]:
    # git archive reads HEAD, never includes ignored/untracked runtime data.
    result = subprocess.run(
        ["git", "archive", "--format=zip", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
        files = {}
        for item in archive.infolist():
            if item.is_dir():
                continue
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Symlinks cannot be released")
            files[item.filename] = archive.read(item)
        return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = committed_files(root)
    version_match = re.search(
        rb'^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$', files["pyproject.toml"], re.M
    )
    if not version_match:
        raise ValueError("No stable version in committed metadata")
    version = version_match.group(1).decode("ascii")
    content = build_archive(files, version)
    args.output.mkdir(parents=True, exist_ok=True)
    name = f"cdn-xhttp-setup-v{version}.zip"
    digest = hashlib.sha256(content).hexdigest()
    # Never overwrite an existing release asset by accident.
    with (args.output / name).open("xb") as target:
        target.write(content)
    with (args.output / (name + ".sha256")).open(
        "x", encoding="ascii", newline="\n"
    ) as target:
        target.write(f"{digest}  {name}\n")
    print(
        json.dumps(
            {"version": version, "archive": str(args.output / name), "sha256": digest}
        )
    )


if __name__ == "__main__":
    main()
