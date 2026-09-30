"""Release integrity, lossless migration and failure isolation without Internet/SSH."""

import hashlib
import io
import json
import stat
import threading
import time
import zipfile

import pytest

from cdn_xhttp import cli, updates


def release_files(version, **extra):
    files = {
        "bootstrap.py": b"# launcher\n",
        "run.cmd": b"@echo off\r\n",
        "run.sh": b"#!/bin/sh\n",
        "pyproject.toml": f'version = "{version}"\n'.encode(),
        "cdn_xhttp/__init__.py": f'__version__ = "{version}"\n'.encode(),
        "cdn_xhttp/cli.py": b"# cli\n",
        **extra,
    }
    manifest = {
        path: hashlib.sha256(value).hexdigest() for path, value in files.items()
    }
    files[updates.MANIFEST] = json.dumps(
        {"version": version, "files": manifest}
    ).encode()
    return files, manifest


def archive_bytes(files, version="0.4.0", entries=()):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, value in files.items():
            archive.writestr(f"cdn-xhttp-setup-{version}/{path}", value)
        for path, value in entries:
            archive.writestr(path, value)
    return stream.getvalue()


def mock_archive(monkeypatch, archive, version="0.4.0", checksum=None):
    release = updates.Release(version)
    digest = checksum or hashlib.sha256(archive).hexdigest()
    called = []

    def fetch(url, maximum, **kwargs):
        called.append(url)
        assert url in {release.url, release.url + ".sha256"}
        return (
            f"{digest}  {release.name}\n".encode()
            if url.endswith(".sha256")
            else archive
        )

    monkeypatch.setattr(updates, "_fetch", fetch)
    return release, called


@pytest.fixture
def installation(tmp_path, monkeypatch):
    root = tmp_path / "setup"
    root.mkdir()
    old, _ = release_files("0.3.0", **{"obsolete.py": b"# removed next release"})
    data = {
        "deployment.json": b'{"uuid":"keep-me"}\r\n',
        "deployment.pending.json": b'{"target":"next","previous":"old"}',
        "deployment.backup-1.json": b"previous-profile",
        "known_hosts": b"pinned-ssh-host-key",
        "result/vless.txt": b"vless://private-token",
        "credentials/private.key": b"private-user-file",
        "folder with spaces/arbitrary.json": b"unknown user data",
        "cdn_xhttp/local-notes.txt": b"user note inside source directory",
        ".venv/old-interpreter-state": b"must remain in backup only",
        "__pycache__/generated.pyc": b"cache",
    }
    for path, value in {**old, **data}.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
    new = release_files("0.4.0")
    monkeypatch.setattr(updates, "download_release", lambda release: new)
    return root, data


@pytest.mark.parametrize(
    "version", ["0.4.0-beta", "v0.4.0", "0.4", "01.2.3", "../x", "0.4.0\n"]
)
def test_only_strict_stable_versions(version):
    with pytest.raises(updates.UpdateError):
        updates.Release(version)


def test_numeric_version_comparison():
    assert updates.version_key("0.10.0") > updates.version_key("0.9.9")


def test_latest_requires_complete_stable_release_and_ignores_supplied_asset_urls(
    monkeypatch,
):
    release = updates.Release("0.4.0")
    data = {
        "tag_name": "v0.4.0",
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": release.name, "browser_download_url": "https://evil.test/code"},
            {"name": release.name + ".sha256"},
        ],
    }
    monkeypatch.setattr(updates, "_fetch", lambda *a, **k: json.dumps(data).encode())
    found = updates.latest_release("0.3.0")
    assert found.url == release.url
    assert updates.latest_release("0.4.0") is None
    data["prerelease"] = True
    with pytest.raises(updates.UpdateError):
        updates.latest_release("0.3.0")
    data["prerelease"] = False
    data["assets"].pop()
    with pytest.raises(updates.UpdateError, match="архива"):
        updates.latest_release("0.3.0")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/RustForNew/cdn-xhttp-setup/releases/x",
        "https://github.com/evil/project/releases/x",
        "https://evil.test/file",
        "https://github.com@evil.test/file",
        "https://github.com:444/RustForNew/cdn-xhttp-setup/releases/x",
    ],
)
def test_untrusted_download_and_redirect_sources_rejected(url):
    assert not updates._official_url(url)
    with pytest.raises(updates.UpdateError):
        updates._OfficialRedirect().redirect_request(None, None, 302, "", {}, url)


def test_check_has_wall_clock_timeout_even_when_dns_stalls(monkeypatch):
    event = threading.Event()
    monkeypatch.setattr(updates, "latest_release", lambda current: event.wait(5))
    started = time.monotonic()
    try:
        assert updates.check_bounded("0.3.0", seconds=0.03) == (None, False)
        assert time.monotonic() - started < 0.5
    finally:
        event.set()


def test_download_has_wall_clock_timeout(monkeypatch):
    event = threading.Event()
    monkeypatch.setattr(updates, "_fetch_blocking", lambda *a, **k: event.wait(5))
    started = time.monotonic()
    try:
        with pytest.raises(updates.UpdateError, match="время"):
            updates._fetch(updates.API_URL, 100, deadline=0.03)
        assert time.monotonic() - started < 0.5
    finally:
        event.set()


def test_archive_integrity_and_manifest_verified(monkeypatch):
    files, manifest = release_files("0.4.0")
    release, called = mock_archive(monkeypatch, archive_bytes(files))
    assert updates.download_release(release) == (files, manifest)
    assert called == [release.url + ".sha256", release.url]


def test_bad_sha_prevents_unpack(monkeypatch):
    release, _ = mock_archive(monkeypatch, b"not even zip", checksum="0" * 64)
    with pytest.raises(updates.UpdateError, match="SHA256"):
        updates.download_release(release)


def test_github_digest_is_checked_as_well(monkeypatch):
    release, _ = mock_archive(monkeypatch, archive_bytes(release_files("0.4.0")[0]))
    with pytest.raises(updates.UpdateError, match="SHA256"):
        updates.download_release(updates.Release(release.version, "0" * 64))


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "C:/drive",
        "cdn-xhttp-setup-0.4.0/../escape",
        "cdn-xhttp-setup-0.4.0/a\\escape",
        "cdn-xhttp-setup-0.4.0/aux.txt",
        "cdn-xhttp-setup-0.4.0/name.",
        "cdn-xhttp-setup-0.4.0/name:stream",
        "cdn-xhttp-setup-0.4.0/BOOTSTRAP.py",
        "another-root/data",
    ],
)
def test_malicious_zip_paths_rejected(monkeypatch, name):
    raw = archive_bytes(release_files("0.4.0")[0], entries=[(name, b"bad")])
    release, _ = mock_archive(monkeypatch, raw)
    with pytest.raises(updates.UpdateError):
        updates.download_release(release)


def test_zip_symlink_rejected(monkeypatch):
    link = zipfile.ZipInfo("cdn-xhttp-setup-0.4.0/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    raw = archive_bytes(release_files("0.4.0")[0], entries=[(link, b"../../escape")])
    release, _ = mock_archive(monkeypatch, raw)
    with pytest.raises(updates.UpdateError, match="Ссылки"):
        updates.download_release(release)


@pytest.mark.parametrize(
    "path",
    [
        "deployment.json",
        "result/vless.txt",
        ".env",
        "known_hosts",
        ".venv/code.py",
        "x.egg-info/PKG-INFO",
    ],
)
def test_release_cannot_ship_user_data_or_generated_state(monkeypatch, path):
    files, _ = release_files("0.4.0", **{path: b"bad"})
    release, _ = mock_archive(monkeypatch, archive_bytes(files))
    with pytest.raises(updates.UpdateError):
        updates.download_release(release)


def test_inner_hash_mismatch_and_unlisted_file_rejected(monkeypatch):
    files, _ = release_files("0.4.0")
    files["bootstrap.py"] = b"changed after manifest"
    release, _ = mock_archive(monkeypatch, archive_bytes(files))
    with pytest.raises(updates.UpdateError, match="внутри ZIP"):
        updates.download_release(release)
    files, _ = release_files("0.4.0")
    files["unlisted"] = b"x"
    mock_archive(monkeypatch, archive_bytes(files))
    with pytest.raises(updates.UpdateError, match="manifest"):
        updates.download_release(release)


def test_install_preserves_all_data_and_complete_verified_backup(installation):
    root, data = installation
    before = updates._inventory(root)
    logs = []
    destination, backup = updates.install_release(
        root, "0.3.0", updates.Release("0.4.0"), log=logs.append
    )
    assert updates._inventory(root) == before == updates._inventory(backup)
    for path, value in data.items():
        assert (backup / path).read_bytes() == value
        if not updates._generated(path):
            assert (destination / path).read_bytes() == value
    assert not (destination / ".venv").exists()
    assert not (destination / "obsolete.py").exists()
    assert not (destination / "__pycache__").exists()
    assert (
        destination / "cdn_xhttp/__init__.py"
    ).read_bytes() == b'__version__ = "0.4.0"\n'
    assert "private-token" not in str(logs)
    assert "private-user-file" not in str(logs)
    if updates.os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o700
        assert stat.S_IMODE(backup.stat().st_mode) == 0o700


def test_missing_manifest_uses_verified_old_release(installation, monkeypatch):
    root, _ = installation
    (root / updates.MANIFEST).unlink()
    calls = []

    def download(release):
        calls.append(release.version)
        return release_files(
            release.version,
            **(
                {"obsolete.py": b"# removed next release"}
                if release.version == "0.3.0"
                else {}
            ),
        )

    monkeypatch.setattr(updates, "download_release", download)
    updates.install_release(
        root, "0.3.0", updates.Release("0.4.0"), log=lambda *a: None
    )
    assert calls == ["0.4.0", "0.3.0"]


@pytest.mark.parametrize("kind", ["directory", "worktree-file", "parent"])
def test_git_checkouts_never_updated(installation, kind):
    root, _ = installation
    target = root.parent / ".git" if kind == "parent" else root / ".git"
    target.mkdir() if kind != "worktree-file" else target.write_text(
        "gitdir: elsewhere"
    )
    with pytest.raises(updates.UpdateError, match="Git checkout"):
        updates.install_release(root, "0.3.0", updates.Release("0.4.0"))


def test_modified_program_file_preserved_and_refused(installation):
    root, _ = installation
    (root / "bootstrap.py").write_bytes(b"user modification")
    with pytest.raises(updates.UpdateError, match="изменены"):
        updates.install_release(root, "0.3.0", updates.Release("0.4.0"))
    assert (root / "bootstrap.py").read_bytes() == b"user modification"
    assert list(root.parent.iterdir()) == [root]


def test_new_release_file_collision_with_unknown_user_file_aborts(
    installation, monkeypatch
):
    root, _ = installation
    monkeypatch.setattr(
        updates,
        "download_release",
        lambda r: release_files(
            "0.4.0", **{"credentials/private.key": b"new program file"}
        ),
    )
    before = updates._inventory(root)
    with pytest.raises(updates.UpdateError, match="конфликтует"):
        updates.install_release(root, "0.3.0", updates.Release("0.4.0"))
    assert updates._inventory(root) == before
    assert list(root.parent.iterdir()) == [root]


def test_copy_failure_rolls_back_new_copy_but_retains_verified_backup(
    installation, monkeypatch
):
    root, _ = installation
    before = updates._inventory(root)
    original = updates._copy_inventory
    calls = []

    def failing_copy(source, target, inventory):
        calls.append(target)
        original(source, target, inventory)
        if len(calls) == 2:
            raise OSError("disk full")

    monkeypatch.setattr(updates, "_copy_inventory", failing_copy)
    with pytest.raises(OSError):
        updates.install_release(root, "0.3.0", updates.Release("0.4.0"))
    assert updates._inventory(root) == before
    assert updates._inventory(calls[0]) == before
    assert not calls[1].exists()


def test_incomplete_backup_is_removed_and_original_intact(installation, monkeypatch):
    root, _ = installation
    before = updates._inventory(root)
    monkeypatch.setattr(
        updates, "_copy_inventory", lambda *a: (_ for _ in ()).throw(OSError("full"))
    )
    with pytest.raises(OSError):
        updates.install_release(root, "0.3.0", updates.Release("0.4.0"))
    assert updates._inventory(root) == before
    assert list(root.parent.iterdir()) == [root]


def test_user_symlink_does_not_read_or_copy_external_secret(installation, tmp_path):
    root, _ = installation
    outside = tmp_path / "outside"
    outside.write_text("external secret")
    try:
        (root / "linked-secret").symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    with pytest.raises(updates.UpdateError, match="ссылка"):
        updates.install_release(root, "0.3.0", updates.Release("0.4.0"))
    assert outside.read_text() == "external secret"


def test_unreadable_directory_cannot_be_silently_omitted_from_backup(
    tmp_path, monkeypatch
):
    def failed_walk(root, *, followlinks, onerror):
        yield str(root), ["private-data"], []
        onerror(PermissionError("cannot list private-data"))

    (tmp_path / "private-data").mkdir()
    monkeypatch.setattr(updates.os, "walk", failed_walk)
    with pytest.raises(updates.UpdateError, match="всю исходную папку"):
        updates._inventory(tmp_path)


def test_concurrent_changes_prevent_publishing_incomplete_snapshot(
    installation, monkeypatch
):
    root, _ = installation
    inventory = updates._inventory
    before = inventory(root)
    reads = []

    def changing_inventory(path):
        value = inventory(path)
        if path == root:
            reads.append(path)
            if len(reads) > 1:
                value["new-user-file"] = ("file", "new digest")
        return value

    monkeypatch.setattr(updates, "_inventory", changing_inventory)
    with pytest.raises(updates.UpdateError, match="изменились"):
        updates.install_release(root, "0.3.0", updates.Release("0.4.0"))
    assert inventory(root) == before
    assert list(root.parent.iterdir()) == [root]


@pytest.mark.skipif(updates.os.name != "nt", reason="Windows DACL check")
def test_private_backup_windows_acl_is_protected_and_owner_system_only(tmp_path):
    directory = updates._private_directory(tmp_path, "private-")
    acl = tmp_path / "acl.txt"
    updates.subprocess.run(
        ["icacls", str(directory), "/save", str(acl)], capture_output=True, check=True
    )
    descriptor = acl.read_text(encoding="utf-16-le")
    # Protected DACL: no inherited Users/Everyone entries, two inheritable grants.
    assert "D:P" in descriptor
    assert descriptor.count("(A;") == 2
    assert ";;;SY)" in descriptor
    assert ";;;S-1-5-21-" in descriptor


def test_network_error_and_refusal_never_install_or_show_secret(monkeypatch):
    monkeypatch.setattr(
        updates,
        "latest_release",
        lambda current: (_ for _ in ()).throw(OSError("proxy://user:password@secret")),
    )
    logs = []
    assert not updates.offer_update(
        "0.3.0", confirm=lambda q: pytest.fail("should not prompt"), log=logs.append
    )
    assert "password" not in str(logs)
    monkeypatch.setattr(
        updates, "check_bounded", lambda current: (updates.Release("0.4.0"), True)
    )
    monkeypatch.setattr(
        updates,
        "install_release",
        lambda *a, **k: pytest.fail("must not install after N"),
    )
    assert not updates.offer_update("0.3.0", confirm=lambda q: False, log=logs.append)


def test_explicit_update_never_contacts_vps_and_still_requires_confirmation(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(
        updates, "offer_update", lambda current, **kwargs: calls.append(kwargs) or True
    )
    monkeypatch.setattr(
        cli, "connect_wizard", lambda *a: pytest.fail("must not enter SSH wizard")
    )
    assert cli.main(["update", "--yes"]) == 0
    assert calls[0]["confirm"] is cli.yes
    assert calls[0]["explicit"] is True


def test_explicit_update_failure_returns_nonzero_without_leaking_network_error(
    monkeypatch, capsys
):
    monkeypatch.setattr(updates, "check_bounded", lambda current: (None, False))
    assert cli.main(["update"]) == 1
    assert "Проверить обновления сейчас не удалось" in capsys.readouterr().err


def test_interactive_update_success_stops_old_wizard(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(updates, "offer_update", lambda *a, **k: True)
    monkeypatch.setattr(
        cli, "connect_wizard", lambda *a: pytest.fail("old wizard must stop")
    )
    assert cli.main(["--config", str(tmp_path / "missing.json")]) == 0


@pytest.mark.parametrize("args", [["--no-update-check"], ["--yes"], []])
def test_disabled_or_noninteractive_check_does_not_use_network(
    monkeypatch, tmp_path, args
):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: bool(args))
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        updates,
        "offer_update",
        lambda *a, **k: pytest.fail("network check should be skipped"),
    )
    monkeypatch.setattr(cli, "connect_wizard", lambda *a: 17)
    assert cli.main([*args, "--config", str(tmp_path / "missing.json")]) == 17
