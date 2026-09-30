"""Release packaging preserves byte integrity and excludes runtime state."""

import hashlib
import io
import json
import zipfile
from unittest.mock import patch

import pytest

from tools.build_release import build_archive
from cdn_xhttp.updates import Release, download_release


def source_files():
    return {
        "run.cmd": b"@echo off\r\n",
        "run.sh": b"#!/bin/sh\n",
        "bootstrap.py": b"# bootstrap\n",
        "pyproject.toml": b'version = "0.3.0"\n',
        "cdn_xhttp/__init__.py": b'__version__ = "0.3.0"\n',
        "docs/updating.md": "Настройки сохраняются.\n".encode(),
    }


def test_every_release_file_matches_manifest_and_archive_is_reproducible():
    files = source_files()
    blob = build_archive(files, "0.3.0")
    assert blob == build_archive(dict(reversed(list(files.items()))), "0.3.0")
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        prefix = "cdn-xhttp-setup-0.3.0/"
        manifest = json.loads(archive.read(prefix + "release-manifest.json"))
        assert manifest["version"] == "0.3.0"
        assert set(manifest["files"]) == set(files)
        for name, expected in files.items():
            actual = archive.read(prefix + name)
            assert actual == expected
            assert hashlib.sha256(actual).hexdigest() == manifest["files"][name]
        assert (archive.getinfo(prefix + "run.sh").external_attr >> 16) & 0o777 == 0o755


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "C:/escape",
        "a\\b",
        "a/../b",
        "known_hosts",
        "deployment.json",
        "deployment.pending.json",
        "result/vless.txt",
        ".venv/file",
        ".git/config",
    ],
)
def test_unsafe_paths_and_private_state_cannot_enter_release(name):
    with pytest.raises(ValueError):
        build_archive({**source_files(), name: b"private"}, "0.3.0")


def test_case_collisions_and_version_mismatch_are_rejected():
    with pytest.raises(ValueError):
        build_archive({**source_files(), "RUN.CMD": b"different"}, "0.3.0")
    with pytest.raises(ValueError):
        build_archive(source_files(), "0.3.1")


def test_release_builder_output_is_accepted_by_real_updater_validator():
    files = source_files()
    raw = build_archive(files, "0.3.0")
    checksum = hashlib.sha256(raw).hexdigest()
    release = Release("0.3.0", digest=checksum)

    def fetch(url, maximum):
        if url == release.url + ".sha256":
            return f"{checksum}  {release.name}\n".encode()
        assert url == release.url
        return raw

    with patch("cdn_xhttp.updates._fetch", side_effect=fetch):
        payload, manifest = download_release(release)
    assert set(manifest) == set(files)
    for path, original in files.items():
        assert payload[path] == original
