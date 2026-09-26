from __future__ import annotations

from collections import deque
import os
from pathlib import Path
import shutil
import subprocess
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from cdn_xhttp import remote


@pytest.fixture
def config():
    return {
        "origin": {"host": "192.0.2.10", "user": "root", "port": 2222},
        "exit": {"host": "192.0.2.11", "user": "root", "port": 22},
        "origin_domain": "origin.example.com",
        "exit_domain": "exit.example.com",
        "cdn_domain": "cdn.example.com",
        "email": "admin@example.com",
        "uuid": "f9168c5e-ceb2-4faa-b6bf-329bf39fa1e4",
        "path": "/api-test",
        "padding_key": "dc",
        "profile": "fast",
        "xray_version": "26.5.9",
    }


def bash_path():
    candidates = [r"C:\Program Files\Git\bin\bash.exe"] if os.name == "nt" else []
    candidates += [shutil.which("bash")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    pytest.skip("bash is unavailable")


@pytest.mark.parametrize("role", ["origin", "exit"])
def test_complete_script_has_valid_bash_syntax(config, role):
    script = remote.render_bootstrap(config, role)
    result = subprocess.run(
        [bash_path(), "-n"],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_bootstrap_rejects_missing_exit_and_invalid_version(config):
    config["exit"] = None
    with pytest.raises(ValueError, match="No exit"):
        remote.render_bootstrap(config, "exit")
    config["xray_version"] = "26.5.9; touch /root/oops"
    with pytest.raises(ValueError, match="Invalid Xray"):
        remote.render_bootstrap(config, "origin")


def test_config_payload_roundtrips_without_shell_interpretation(config):
    import base64
    import json
    import re

    # Renderer inputs are quoted even if a caller bypasses CLI validation.
    config["email"] = "a'$(touch /tmp/never)@example.com"
    config["path"] = "/example'$(echo never)"
    script = remote.render_bootstrap(config, "origin")
    match = re.search(
        r"printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d > \"\$STAGING/config.json\"",
        script,
    )
    payload = json.loads(base64.b64decode(match.group(1)))
    assert (
        payload["inbounds"][0]["streamSettings"]["xhttpSettings"]["path"]
        == config["path"]
    )
    result = subprocess.run(
        [bash_path(), "-n"],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr


def test_os_release_does_not_overwrite_pinned_xray_version(config):
    script = remote.render_bootstrap(config, "origin").split("fail()", 1)[0]
    script += 'VERSION="24.04.1 LTS (Noble Numbat)"\nprintf "%s" "$XRAY_VERSION"\n'
    result = subprocess.run(
        [bash_path()],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0
    assert result.stdout == "26.5.9"


class FakeChannel:
    def __init__(self, chunks=(), status=0):
        self.chunks = deque(chunks)
        self.status = status
        self.sent = b""
        self.closed = False
        self.command = None

    def set_combine_stderr(self, value):
        assert value is True

    def exec_command(self, command):
        self.command = command

    def sendall(self, data):
        self.sent += data

    def shutdown_write(self):
        pass

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, size):
        return self.chunks.popleft()

    def exit_status_ready(self):
        # Deliberately ready while unread data still exists.
        return True

    def recv_exit_status(self):
        assert not self.chunks
        return self.status

    def close(self):
        self.closed = True


def channel_client(channel):
    client = MagicMock()
    client.get_transport.return_value.is_active.return_value = True
    client.get_transport.return_value.open_session.return_value = channel
    return client


def test_stream_drains_before_exit_and_redacts_chunk_boundaries():
    channel = FakeChannel([b"Error sec", b"ret-pass\nline2\ntrailing secret-pass"])
    logs = []
    remote._stream_command(
        channel_client(channel),
        "sudo script",
        stdin_secret="secret-pass",
        log=logs.append,
        secrets=["secret-pass"],
    )
    assert channel.sent == b"secret-pass\n"
    assert logs == ["Error [REDACTED]", "line2", "trailing [REDACTED]"]
    assert channel.closed
    assert "secret-pass" not in channel.command


def test_stream_failure_still_closes_channel():
    channel = FakeChannel([b"nginx test failed\n"], status=9)
    logs = []
    with pytest.raises(remote.RemoteError, match="status 9"):
        remote._stream_command(
            channel_client(channel), "script", log=logs.append, secrets=[]
        )
    assert logs == ["nginx test failed"]
    assert channel.closed


def test_stream_timeout_is_enforced_during_continuous_output():
    channel = FakeChannel([b"still running\n"] * 100)
    with patch.object(remote.time, "monotonic", side_effect=[0, 0.5, 1.5]):
        with pytest.raises(remote.RemoteError, match="timed out"):
            remote._stream_command(
                channel_client(channel),
                "script",
                log=lambda _: None,
                secrets=[],
                timeout=1,
            )
    assert channel.closed
    assert len(channel.chunks) == 99


def mock_ssh_client():
    client = MagicMock()
    stdin, stdout, stderr = MagicMock(), MagicMock(), MagicMock()
    stdout.read.return_value = b"/tmp/cdn-xhttp-ssh.Abcd1234\n"
    stdout.channel.recv_exit_status.return_value = 0
    client.exec_command.return_value = (stdin, stdout, stderr)
    return client


def test_deploy_uses_sudo_stdin_and_private_sftp_cleanup(config, tmp_path):
    config["origin"]["user"] = "ubuntu"
    client = mock_ssh_client()
    with (
        patch("paramiko.SSHClient", return_value=client),
        patch.object(remote, "render_bootstrap", return_value="private config\n"),
        patch.object(remote, "_stream_command") as run,
    ):
        remote.deploy_server(
            config,
            "origin",
            password="ssh-secret",
            sudo_password="sudo-secret",
            known_hosts=tmp_path / "known_hosts",
            confirm_host=lambda _: True,
            log=lambda _: None,
        )
    args, kwargs = run.call_args
    assert args[1].startswith("sudo -k -S -p '' -- bash -- /tmp/")
    assert "ssh-secret" not in args[1] and "sudo-secret" not in args[1]
    assert kwargs["stdin_secret"] == "sudo-secret"
    assert client.connect.call_args.kwargs["look_for_keys"] is False
    sftp = client.open_sftp.return_value.__enter__.return_value
    sftp.chmod.assert_called_once_with(
        "/tmp/cdn-xhttp-ssh.Abcd1234/bootstrap.sh", 0o600
    )
    sftp.remove.assert_called_once_with("/tmp/cdn-xhttp-ssh.Abcd1234/bootstrap.sh")
    sftp.rmdir.assert_called_once_with("/tmp/cdn-xhttp-ssh.Abcd1234")
    client.close.assert_called_once()


def test_deploy_redacts_every_uuid_and_does_not_reuse_ssh_password_for_sudo(
    config, tmp_path
):
    config["origin"]["user"] = "ubuntu"
    extra_uuid = "2c64b72e-adc2-4cd7-9b13-ab03e53c79cd"
    config["uuids"] = [config["uuid"], extra_uuid]
    client = mock_ssh_client()
    with (
        patch("paramiko.SSHClient", return_value=client),
        patch.object(remote, "render_bootstrap", return_value="script"),
        patch.object(remote, "_stream_command") as run,
    ):
        remote.deploy_server(
            config,
            "origin",
            password="ssh-secret",
            sudo_password=None,
            known_hosts=tmp_path / "known_hosts",
            confirm_host=lambda _: True,
            log=lambda _: None,
        )
    assert run.call_args.kwargs["stdin_secret"] is None
    secrets = run.call_args.kwargs["secrets"]
    assert (
        remote._redact(f"users: {config['uuid']}, {extra_uuid}", secrets)
        == "users: [REDACTED], [REDACTED]"
    )
    assert "ssh-secret" in secrets


def test_unknown_host_requires_fingerprint_acceptance(config, tmp_path):
    client = mock_ssh_client()
    accepted = []
    key = paramiko.RSAKey.generate(1024)

    def connect(*args, **kwargs):
        policy = client.set_missing_host_key_policy.call_args.args[0]
        policy.missing_host_key(client, "[192.0.2.10]:2222", key)

    client.connect.side_effect = connect
    with (
        patch("paramiko.SSHClient", return_value=client),
        patch.object(remote, "render_bootstrap", return_value="script"),
    ):
        with pytest.raises(remote.RemoteError, match="not accepted"):
            remote.deploy_server(
                config,
                "origin",
                password="secret",
                sudo_password=None,
                known_hosts=tmp_path / "known_hosts",
                confirm_host=lambda prompt: accepted.append(prompt) or False,
                log=lambda _: None,
            )
    assert len(accepted) == 1
    assert accepted[0].startswith("[192.0.2.10]:2222: ssh-rsa SHA256:")
    assert not (tmp_path / "known_hosts").exists()
    client.exec_command.assert_not_called()


def test_changed_host_key_is_never_prompted_or_accepted(config, tmp_path):
    client = mock_ssh_client()
    key = paramiko.RSAKey.generate(1024)
    client.connect.side_effect = paramiko.BadHostKeyException("192.0.2.10", key, key)
    confirm = MagicMock(return_value=True)
    with (
        patch("paramiko.SSHClient", return_value=client),
        patch.object(remote, "render_bootstrap", return_value="script"),
    ):
        with pytest.raises(remote.RemoteError, match="host key changed"):
            remote.deploy_server(
                config,
                "origin",
                password="secret",
                sudo_password=None,
                known_hosts=tmp_path / "known_hosts",
                confirm_host=confirm,
                log=lambda _: None,
            )
    confirm.assert_not_called()
    client.exec_command.assert_not_called()


def test_failure_trap_restores_previous_files_and_removes_new_files(tmp_path):
    """Execute the actual rollback implementation against temporary paths."""
    import shlex

    existing = tmp_path / "existing-config"
    new = tmp_path / "new-config"
    backup = tmp_path / "backup"
    stage = tmp_path / "staging"
    service_log = tmp_path / "services.txt"
    stage.mkdir()
    existing.write_text("replacement", encoding="utf-8")
    new.write_text("new", encoding="utf-8")

    def shell_path(path):
        # Git bash /c/... addresses the same temporary directory on Windows.
        value = path.as_posix()
        if os.name == "nt":
            value = "/" + value[0].lower() + value[2:]
        return value

    existing_sh = shell_path(existing)
    new_sh = shell_path(new)
    backup_sh = shell_path(backup)
    # Bash backup stores absolute paths beneath files, exactly like cp --parents.
    stored = Path(str(backup / "files") + existing_sh)
    stored.parent.mkdir(parents=True)
    stored.write_text("original", encoding="utf-8")
    rollback = remote._PREFLIGHT.split("restore_service() {", 1)[1].split(
        'note "Preflight passed', 1
    )[0]
    script = "set -Eeuo pipefail\n"
    script += "note() { :; }\n"
    script += f"systemctl() {{ printf '%s\\n' \"$*\" >> {shlex.quote(shell_path(service_log))}; }}\n"
    settings = {
        "BACKUP": backup_sh,
        "STAGING": shell_path(stage),
        "ROLE": "origin",
        "MUTATING": "1",
        "COMPLETE": "0",
        "XRAY_ACTIVE": "1",
        "XRAY_ENABLED": "1",
        "HEALTH_ACTIVE": "0",
        "HEALTH_ENABLED": "0",
        "NGINX_ACTIVE": "1",
        "NGINX_ENABLED": "0",
    }
    script += (
        "\n".join(f"{name}={shlex.quote(value)}" for name, value in settings.items())
        + "\n"
    )
    script += f"BACKUP_PATHS=({shlex.quote(existing_sh)} {shlex.quote(new_sh)})\n"
    script += "restore_service() {" + rollback
    script += "exit 17\n"
    result = subprocess.run(
        [bash_path()],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 17, result.stderr
    assert existing.read_text(encoding="utf-8") == "original"
    assert not new.exists()
    assert not stage.exists()
    services = service_log.read_text(encoding="utf-8")
    assert "restart cdn-xhttp.service" in services
    assert "disable cdn-xhttp-health.service" in services
    assert "stop cdn-xhttp-health.service" in services
    assert "restart nginx.service" in services
    assert backup.exists()


def test_recovery_roundtrip_and_foreign_runtime_rejected(config):
    import copy
    import json
    from cdn_xhttp.config import validate
    from cdn_xhttp.render import origin_xray

    c = validate(config)
    payload = {
        "deployment.json": json.loads(remote._identity(c, "origin")),
        "config.json": origin_xray(c),
        "setup.json": c,
    }
    login = {**c["origin"], "user": "ubuntu", "port": 2223}
    recovered = remote._recovered_config(payload, login)
    assert recovered == {**c, "origin": login}
    changed = copy.deepcopy(payload)
    changed["config.json"]["outbounds"][0]["settings"]["vnext"][0]["address"] = (
        "192.0.2.99"
    )
    with pytest.raises(remote.RemoteError, match="differs"):
        remote._recovered_config(changed, login)
    assert remote._recovered_config({}, login) is None


@pytest.mark.parametrize("bridge", [True, False])
def test_legacy_recovery_preserves_all_users_and_transport(config, bridge):
    import json
    from cdn_xhttp.config import validate
    from cdn_xhttp.render import origin_xray

    if not bridge:
        config["exit"] = None
        config.pop("exit_domain")
    config["uuids"] = [config["uuid"], "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
    c = validate(config)
    payload = {
        "deployment.json": json.loads(remote._identity(c, "origin")),
        "config.json": origin_xray(c),
    }
    recovered = remote._recovered_config(payload, c["origin"])
    assert recovered.pop("_recovered_legacy") is True
    assert recovered["email"] == ""
    recovered["email"] = c["email"]
    assert origin_xray(validate(recovered)) == origin_xray(c)
    assert recovered["uuids"] == c["uuids"]


def test_recovery_over_ssh_is_read_only_and_never_logs_private_payload(
    config, tmp_path
):
    import base64
    import json
    from cdn_xhttp.config import validate
    from cdn_xhttp.render import origin_xray

    c = validate(config)
    c["origin"]["user"] = "ubuntu"
    payload = {
        "deployment.json": json.loads(remote._identity(c, "origin")),
        "config.json": origin_xray(c),
        "setup.json": c,
    }
    line = "CDN_SETUP:" + base64.b64encode(json.dumps(payload).encode()).decode()
    client = MagicMock()

    def run(client, command, **kwargs):
        assert command.startswith("sudo -k -S -p '' -- python3 -c ")
        assert c["uuid"] not in command and "sudo-secret" not in command
        assert kwargs["stdin_secret"] == "sudo-secret"
        kwargs["log"](line)

    with (
        patch.object(remote, "_connect", return_value=client),
        patch.object(remote, "_stream_command", side_effect=run),
    ):
        recovered = remote.recover_config(
            c["origin"],
            password="ssh-secret",
            sudo_password="sudo-secret",
            known_hosts=tmp_path / "known_hosts",
            confirm_host=lambda _: True,
        )
    assert recovered == c
    client.open_sftp.assert_not_called()
    client.close.assert_called_once()


@pytest.mark.parametrize("role", ["origin", "exit"])
def test_managed_domain_update_script_is_valid_and_saves_private_setup(config, role):
    import copy
    import base64
    import json
    import re

    updated = copy.deepcopy(config)
    updated["origin_domain"] = "new-origin.example.com"
    updated["cdn_domain"] = "new-cdn.example.com"
    script = remote.render_bootstrap(updated, role, previous=config)
    result = subprocess.run(
        [bash_path(), "-n"],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    match = re.search(
        r"printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d > \"\$STAGING/setup.json\"",
        script,
    )
    assert json.loads(base64.b64decode(match.group(1))) == updated
    assert "install -m 600 -o root -g root" in script


@pytest.mark.parametrize("runtime_kind", ["previous", "target", "changed"])
def test_update_compare_and_swap_allows_retry_but_refuses_concurrent_change(
    config, tmp_path, runtime_kind
):
    import base64
    import copy
    import json
    from cdn_xhttp.render import origin_xray

    updated = copy.deepcopy(config)
    updated["uuids"] = [config["uuid"], "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
    previous = origin_xray(config)
    target = origin_xray(updated)
    actual = previous if runtime_kind == "previous" else target
    if runtime_kind == "changed":
        actual = copy.deepcopy(target)
        actual["inbounds"][0]["port"] = 9000
    runtime = tmp_path / "runtime.json"
    runtime.write_text(json.dumps(actual), encoding="utf-8")
    source = remote._PREFLIGHT.split("<<'PY_PREVIOUS'\n", 1)[1].split(
        "\nPY_PREVIOUS", 1
    )[0]
    source = source.replace("'/etc/cdn-xhttp/config.json'", repr(runtime.as_posix()))
    import sys

    result = subprocess.run(
        [sys.executable, "-c", source],
        env={
            **os.environ,
            "PREVIOUS_XRAY": base64.b64encode(json.dumps(previous).encode()).decode(),
            "CURRENT_XRAY": base64.b64encode(json.dumps(target).encode()).decode(),
        },
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) == (runtime_kind != "changed")


def test_legacy_certificate_ownership_survives_a_to_b_to_a(tmp_path):
    import base64
    import json
    import sys

    root = tmp_path / "ownership"
    (root / "certificates").mkdir(parents=True)
    a = {"role": "origin", "domain": "a.example.com", "cdn_domain": "cdn.example.com"}
    b = {**a, "domain": "b.example.com"}
    (root / "certificate-owner.json").write_text(json.dumps(a), encoding="utf-8")
    source = remote._INSTALL.split("<<'PY_KEEP_CERT'\n", 1)[1].split(
        "\nPY_KEEP_CERT", 1
    )[0]
    source = source.replace("'/var/lib/cdn-xhttp'", repr(root.as_posix()))
    subprocess.run([sys.executable, "-c", source], check=True)
    assert json.loads((root / "certificates/a.example.com.json").read_text()) == a
    (root / "certificate-owner.json").write_text(json.dumps(b), encoding="utf-8")
    guard = remote._PREFLIGHT.split("<<'PY_CERT'\n", 1)[1].split("\nPY_CERT", 1)[0]
    guard = guard.replace(
        "'/var/lib/cdn-xhttp/certificates'", repr((root / "certificates").as_posix())
    )
    subprocess.run(
        [
            sys.executable,
            "-c",
            guard,
            base64.b64encode(json.dumps(b).encode()).decode(),
            "a.example.com",
        ],
        check=True,
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            guard,
            base64.b64encode(json.dumps(b).encode()).decode(),
            "unowned.example.com",
        ],
        capture_output=True,
    )
    assert result.returncode != 0


@pytest.mark.parametrize(
    "changed_field", ["name", "profile", "email", "connect_address", "ssh_login"]
)
def test_metadata_compare_and_swap_rejects_concurrent_settings_but_accepts_local_only(
    config, tmp_path, changed_field
):
    import base64
    import copy
    import json
    import sys
    from cdn_xhttp.config import validate

    previous = validate(config)
    target = {**previous, "name": "My new name"}
    actual = copy.deepcopy(previous)
    changes = {
        "name": "Someone else's name",
        "profile": "original",
        "email": "other@example.com",
        "connect_address": "8.8.8.8",
    }
    if changed_field == "ssh_login":
        actual["origin"]["user"] = "ubuntu"
    else:
        actual[changed_field] = changes[changed_field]
    setup = tmp_path / "setup.json"
    setup.write_text(json.dumps(actual), encoding="utf-8")
    source = remote._PREFLIGHT.split("<<'PY_SETUP'\n", 1)[1].split("\nPY_SETUP", 1)[0]
    source = source.replace("'/etc/cdn-xhttp/setup.json'", repr(setup.as_posix()))
    result = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        env={
            **os.environ,
            "PREVIOUS_SETUP": base64.b64encode(json.dumps(previous).encode()).decode(),
            "TARGET_SETUP": base64.b64encode(json.dumps(target).encode()).decode(),
        },
    )
    assert (result.returncode == 0) == (
        changed_field in {"connect_address", "ssh_login"}
    )
