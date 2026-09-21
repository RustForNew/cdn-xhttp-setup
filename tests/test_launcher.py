"""Regression checks for the local launcher; no SSH or package downloads."""

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.fixture
def launcher(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "launcher_bootstrap", Path(__file__).resolve().parents[1] / "bootstrap.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "ENV", tmp_path / ".venv")
    monkeypatch.setattr(module, "STAMP", tmp_path / ".venv" / ".cdn-xhttp-install")
    (tmp_path / "pyproject.toml").write_text('version = "1.0"\n', encoding="utf-8")
    return module


def test_preparation_installs_once_then_updates_on_metadata_change(launcher, monkeypatch):
    commands = []

    def setup(command):
        commands.append(command)
        launcher.ENV.mkdir(exist_ok=True)

    monkeypatch.setattr(launcher, "run_setup", setup)
    monkeypatch.setattr(launcher, "environment_works", launcher.ENV.is_dir)
    monkeypatch.setattr(launcher, "dependencies_work", lambda: True)
    launcher.prepare()
    assert len(commands) == 2  # Create the environment, then install.
    launcher.prepare()
    assert len(commands) == 2
    (launcher.ROOT / "pyproject.toml").write_text('version = "1.1"\n', encoding="utf-8")
    launcher.prepare()
    assert len(commands) == 3
    assert "pip" in commands[-1]


def test_global_python_is_never_accepted_as_the_project_environment(launcher, monkeypatch):
    monkeypatch.setattr(launcher, "PYTHON", Path(sys.executable))
    assert not launcher.environment_works()


def test_linked_environment_is_not_modified(launcher, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        launcher.ENV.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks is not permitted on this system")
    with pytest.raises(RuntimeError, match="обычной папкой"):
        launcher.prepare()


def test_setup_failure_displays_diagnostics(launcher, monkeypatch, capsys):
    monkeypatch.setattr(
        launcher.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "Package download failed\n"),
    )
    with pytest.raises(RuntimeError, match="Причина указана выше"):
        launcher.run_setup(["python", "-m", "pip"])
    assert "Package download failed" in capsys.readouterr().err


def test_launcher_preserves_arguments_and_exit_code(launcher, monkeypatch):
    monkeypatch.setattr(launcher, "prepare", lambda: None)
    monkeypatch.setattr(launcher.sys, "argv", ["bootstrap.py", "plan", "--config", "folder name/config.json"])
    received = []

    def call(command, **kwargs):
        received.extend(command)
        return 2

    monkeypatch.setattr(launcher.subprocess, "call", call)
    assert launcher.main() == 2
    assert received[-3:] == ["plan", "--config", "folder name/config.json"]
