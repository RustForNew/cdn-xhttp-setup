"""Prepare the local Python environment, then run the command-line program."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
ENV = ROOT / ".venv"
PYTHON = ENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
STAMP = ENV / ".cdn-xhttp-install"


def run_setup(command: list[str]) -> None:
    result = subprocess.run(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode:
        print(result.stdout, file=sys.stderr, end="")
        raise RuntimeError("Не удалось подготовить Python-окружение. Причина указана выше.")


def environment_works() -> bool:
    if not PYTHON.is_file():
        return False
    try:
        code = (
            "import sys; from pathlib import Path; "
            "sys.exit(not (sys.version_info >= (3, 10) and "
            "sys.prefix != sys.base_prefix and "
            "Path(sys.prefix).resolve() == Path(sys.argv[1]).resolve()))"
        )
        result = subprocess.run(
            [str(PYTHON), "-c", code, str(ENV)],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except OSError:
        return False


def dependencies_work() -> bool:
    code = (
        "import paramiko, cdn_xhttp; from importlib.metadata import version; "
        "assert version('cdn-xhttp-setup') == cdn_xhttp.__version__"
    )
    return subprocess.run(
        [str(PYTHON), "-c", code], cwd=ROOT,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def prepare() -> None:
    # Refuse linked environments before clearing or installing into them.
    if ENV.is_symlink() or ENV.resolve() != ENV or (ENV.exists() and not ENV.is_dir()):
        raise RuntimeError("Папка .venv должна быть обычной папкой внутри программы.")

    fingerprint = hashlib.sha256(
        str(ROOT).encode("utf-8") + b"\0" + (ROOT / "pyproject.toml").read_bytes()
    ).hexdigest()
    current = STAMP.read_text(encoding="utf-8").strip() if STAMP.is_file() else ""
    healthy = environment_works()
    if healthy and current == fingerprint and dependencies_work():
        return

    print("Подготовка программы: первый запуск или обновление. Подождите…", flush=True)
    if not healthy:
        run_setup([sys.executable, "-m", "venv", "--clear", str(ENV)])
        if not environment_works():
            raise RuntimeError("Не удалось создать отдельное Python-окружение в .venv.")
    run_setup([
        str(PYTHON), "-m", "pip", "install", "--disable-pip-version-check", "-e", str(ROOT),
    ])
    if not dependencies_work():
        raise RuntimeError("Не удалось загрузить зависимости. Удалите папку .venv и повторите запуск.")
    STAMP.write_text(fingerprint + "\n", encoding="utf-8")


def main() -> int:
    if sys.version_info < (3, 10):
        print("Нужен Python 3.10 или новее. Обновите Python и повторите запуск.", file=sys.stderr)
        return 1
    os.environ["PYTHONUTF8"] = "1"
    try:
        prepare()
        return subprocess.call([str(PYTHON), "-m", "cdn_xhttp", *sys.argv[1:]], cwd=ROOT)
    except (OSError, RuntimeError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
