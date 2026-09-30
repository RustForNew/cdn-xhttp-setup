"""Opt-in release updates into a separate folder; never change the running copy."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid
import zipfile

REPOSITORY = "RustForNew/cdn-xhttp-setup"
RELEASES_URL = f"https://github.com/{REPOSITORY}/releases"
API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
CHECK_SECONDS = 3.0
MANIFEST = "release-manifest.json"
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
REQUIRED = {
    "bootstrap.py",
    "run.cmd",
    "run.sh",
    "pyproject.toml",
    "cdn_xhttp/__init__.py",
}
# Only disposable Python state is omitted from the new copy, never from backup.
GENERATED = {".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}


class UpdateError(RuntimeError):
    pass


def version_key(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value
    ):
        raise UpdateError("Неизвестный формат стабильной версии.")
    return tuple(int(part) for part in value.split("."))


@dataclass(frozen=True)
class Release:
    version: str
    digest: str | None = None

    def __post_init__(self):
        version_key(self.version)
        if self.digest is not None and not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            raise UpdateError("Некорректная контрольная сумма релиза.")

    @property
    def name(self) -> str:
        return f"cdn-xhttp-setup-v{self.version}.zip"

    @property
    def url(self) -> str:
        return f"https://github.com/{REPOSITORY}/releases/download/v{self.version}/{self.name}"

    @property
    def page(self) -> str:
        return f"{RELEASES_URL}/tag/v{self.version}"


def _official_url(url: str) -> bool:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
    ):
        return False
    if parsed.hostname == "github.com":
        return parsed.path.startswith(f"/{REPOSITORY}/releases/")
    if parsed.hostname == "api.github.com":
        return parsed.path.startswith(f"/repos/{REPOSITORY}/releases/")
    return parsed.hostname in {
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
    }


class _OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if not _official_url(newurl):
            raise UpdateError(
                "Источник обновления перенаправил запрос за пределы GitHub."
            )
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def _fetch_blocking(
    url: str, maximum: int, *, timeout: float, deadline: float
) -> bytes:
    if not _official_url(url):
        raise UpdateError("Обновление разрешено только из официального репозитория.")
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CDN-XHTTP-Setup-Updater",
            "Accept": "application/vnd.github+json"
            if url.startswith("https://api.github.com/")
            else "application/octet-stream",
        },
    )
    started = time.monotonic()
    with urllib.request.build_opener(_OfficialRedirect()).open(
        request, timeout=timeout
    ) as response:
        if response.status != 200 or not _official_url(response.geturl()):
            raise UpdateError("Не удалось получить официальный файл обновления.")
        chunks, length = [], 0
        while True:
            if time.monotonic() - started > deadline:
                raise UpdateError("Истекло время загрузки обновления.")
            chunk = response.read(min(65536, maximum + 1 - length))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            length += len(chunk)
            if length > maximum:
                raise UpdateError("Файл обновления превышает допустимый размер.")


def _fetch(
    url: str, maximum: int, *, timeout: float = 10.0, deadline: float = 60.0
) -> bytes:
    # DNS and proxy discovery are not bounded by urllib's socket timeout.
    # This worker only reads public release bytes, never mutates local files.
    result = queue.Queue(maxsize=1)

    def worker():
        try:
            result.put(
                (
                    True,
                    _fetch_blocking(url, maximum, timeout=timeout, deadline=deadline),
                )
            )
        except Exception as exc:
            result.put((False, exc))

    threading.Thread(target=worker, daemon=True, name="cdn-update-download").start()
    try:
        ok, value = result.get(timeout=deadline)
    except queue.Empty:
        raise UpdateError("Истекло время загрузки обновления.") from None
    if not ok:
        raise value
    return value


def latest_release(current: str) -> Release | None:
    """Only release metadata is read; never trust asset URLs from that metadata."""
    data = json.loads(_fetch(API_URL, 1024 * 1024, timeout=2.0, deadline=CHECK_SECONDS))
    if (
        not isinstance(data, dict)
        or data.get("draft") is not False
        or data.get("prerelease") is not False
    ):
        raise UpdateError("Ответ GitHub не содержит стабильного релиза.")
    tag = data.get("tag_name", "")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise UpdateError("Некорректный тег релиза.")
    release = Release(tag[1:])
    if version_key(release.version) <= version_key(current):
        return None
    assets = data.get("assets", [])
    if not isinstance(assets, list):
        raise UpdateError("Некорректный список файлов релиза.")
    names = [asset.get("name") for asset in assets if isinstance(asset, dict)]
    if names.count(release.name) != 1 or names.count(release.name + ".sha256") != 1:
        raise UpdateError("В релизе пока нет проверяемого архива программы.")
    entry = next(
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == release.name
    )
    digest = entry.get("digest")
    if digest is not None:
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise UpdateError("GitHub вернул неизвестный тип контрольной суммы.")
        release = Release(release.version, digest[7:])
    return release


def check_bounded(
    current: str, seconds: float = CHECK_SECONDS
) -> tuple[Release | None, bool]:
    """Return within the wall-clock budget even when system DNS/proxy resolution stalls."""
    result = queue.Queue(maxsize=1)

    def worker():
        try:
            result.put((latest_release(current), True))
        except Exception:
            # Never display proxy credentials, raw server text or a traceback.
            result.put((None, False))

    threading.Thread(target=worker, daemon=True, name="cdn-update-check").start()
    try:
        return result.get(timeout=seconds)
    except queue.Empty:
        return None, False


def _safe_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or ":" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise UpdateError("В архиве обнаружено недопустимое имя файла.")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(
            part in {"", ".", ".."} or part.endswith((".", " ")) for part in path.parts
        )
    ):
        raise UpdateError("Архив содержит путь за пределами папки программы.")
    if any(
        re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)
        for part in path.parts
    ):
        raise UpdateError("Архив содержит зарезервированное имя Windows.")
    return value


def _manifest(raw: bytes, version: str) -> dict[str, str]:
    try:
        data = json.loads(raw)
        files = data["files"]
        if (
            set(data) != {"version", "files"}
            or data["version"] != version
            or not isinstance(files, dict)
            or not REQUIRED <= set(files)
            or MANIFEST in files
        ):
            raise ValueError
        seen = set()
        for path, digest in files.items():
            _safe_path(path)
            if (
                path.casefold() in seen
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise ValueError
            seen.add(path.casefold())
        return files
    except (ValueError, TypeError, KeyError) as exc:
        raise UpdateError("Некорректный manifest файлов релиза.") from exc


def download_release(release: Release) -> tuple[dict[str, bytes], dict[str, str]]:
    checksum = _fetch(release.url + ".sha256", 1024).decode("ascii").strip()
    match = re.fullmatch(
        r"([0-9a-fA-F]{64})[ \t]+\*?" + re.escape(release.name), checksum
    )
    if not match:
        raise UpdateError("Файл SHA256 не соответствует архиву релиза.")
    raw = _fetch(release.url, MAX_ARCHIVE)
    actual = hashlib.sha256(raw).hexdigest()
    if actual != match[1].lower() or (release.digest and actual != release.digest):
        raise UpdateError("SHA256 обновления не совпадает. Архив не установлен.")
    files, seen, size = {}, set(), 0
    prefix = f"cdn-xhttp-setup-{release.version}/"
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if len(archive.infolist()) > 5000:
                raise UpdateError("В архиве слишком много файлов.")
            for item in archive.infolist():
                name = item.filename.rstrip("/") if item.is_dir() else item.filename
                _safe_path(name)
                mode = item.external_attr >> 16
                if (
                    stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or item.flag_bits & 1
                ):
                    raise UpdateError(
                        "Ссылки, специальные и зашифрованные файлы в обновлении запрещены."
                    )
                if name == prefix[:-1] and item.is_dir():
                    continue
                if not item.filename.startswith(prefix):
                    raise UpdateError("В архиве неверная корневая папка.")
                relative = _safe_path(name[len(prefix) :])
                if relative.casefold() in seen:
                    raise UpdateError("В архиве повторяются имена файлов.")
                seen.add(relative.casefold())
                if item.is_dir():
                    continue
                size += item.file_size
                if size > MAX_EXPANDED:
                    raise UpdateError("Распакованное обновление слишком велико.")
                files[relative] = archive.read(item)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        if isinstance(exc, UpdateError):
            raise
        raise UpdateError("Не удалось проверить ZIP обновления.") from exc
    if MANIFEST not in files:
        raise UpdateError("В архиве нет списка файлов программы.")
    manifest = _manifest(files[MANIFEST], release.version)
    if set(files) != set(manifest) | {MANIFEST}:
        raise UpdateError("Содержимое ZIP отличается от manifest релиза.")
    for path, digest in manifest.items():
        if hashlib.sha256(files[path]).hexdigest() != digest:
            raise UpdateError("Контрольная сумма файла внутри ZIP не совпадает.")
        parts = PurePosixPath(path).parts
        if any(
            part in GENERATED or part == ".git" or part.endswith(".egg-info")
            for part in parts
        ):
            raise UpdateError("Архив содержит локальное состояние Python/Git.")
        if parts[0] in {
            "known_hosts",
            "result",
            "preview",
            "clients",
            "vless.txt",
            "client.json",
            "xhttp-extra.json",
            "status.json",
        } or parts[0].startswith(("deployment", ".env")):
            raise UpdateError("Архив пытается установить пользовательские настройки.")
    init = files["cdn_xhttp/__init__.py"].decode("utf-8-sig")
    if not re.search(
        r"(?m)^__version__\s*=\s*['\"]" + re.escape(release.version) + r"['\"]\s*$",
        init,
    ):
        raise UpdateError("Версия пакета не соответствует релизу.")
    return files, manifest


def _is_link(path: Path) -> bool:
    value = path.lstat()
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _private_directory(parent: Path, prefix: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    try:
        if os.name != "nt":
            path.chmod(0o700)
        else:
            who = subprocess.run(
                ["whoami", "/user", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            sid = next(csv.reader(io.StringIO(who.stdout)))[1]
            if not re.fullmatch(r"S-1-[0-9-]+", sid):
                raise UpdateError("Не удалось определить владельца резервной копии.")
            subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"*{sid}:(OI)(CI)F",
                    "*S-1-5-18:(OI)(CI)F",
                ],
                capture_output=True,
                check=True,
                timeout=10,
            )
        return path
    except BaseException:
        path.rmdir()
        raise


def _inventory(root: Path) -> dict[str, tuple[str, str]]:
    """Read without following links; Linux venv links are copied only to backup."""
    result = {}

    def unreadable(error):
        raise UpdateError(
            "Не удалось прочитать всю исходную папку. Полная резервная копия не подтверждена."
        ) from error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in dirs[:] + files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if _is_link(path):
                if PurePosixPath(relative).parts[0] != ".venv" or not path.is_symlink():
                    raise UpdateError(
                        "В папке есть ссылка/junction. Используйте ручное обновление с сохранением её цели."
                    )
                result[relative] = ("link", os.readlink(path))
                if name in dirs:
                    dirs.remove(name)
            elif path.is_dir():
                result[relative] = ("dir", "")
            elif path.is_file():
                with path.open("rb") as stream:
                    digest = (
                        hashlib.file_digest(stream, "sha256").hexdigest()
                        if hasattr(hashlib, "file_digest")
                        else _hash_stream(stream)
                    )
                result[relative] = ("file", digest)
            else:
                raise UpdateError(
                    "В папке есть специальный файл. Используйте ручное обновление."
                )
    return result


def _hash_stream(stream) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _copy_inventory(source: Path, target: Path, inventory: dict) -> None:
    for relative, (kind, _) in sorted(
        inventory.items(), key=lambda row: (len(PurePosixPath(row[0]).parts), row[0])
    ):
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if kind == "dir":
            destination.mkdir(exist_ok=True)
        else:
            shutil.copy2(source / relative, destination, follow_symlinks=False)


def _generated(path: str) -> bool:
    return any(
        part in GENERATED or part.endswith(".egg-info")
        for part in PurePosixPath(path).parts
    )


def install_release(
    root: Path, current: str, release: Release, log=print
) -> tuple[Path, Path]:
    """Prepare a verified sibling copy, keeping the running folder byte-for-byte intact."""
    root = root.absolute()
    if _is_link(root) or root.resolve() != root:
        raise UpdateError("Папка программы не должна быть ссылкой.")
    if any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise UpdateError(
            "Git checkout автоматически не обновляется. Обновите его через Git, сохранив свои изменения."
        )
    if not all((root / path).is_file() for path in REQUIRED):
        raise UpdateError(
            "Автоустановка доступна для полного ZIP программы. Для pip используйте свой способ установки."
        )
    if version_key(release.version) <= version_key(current):
        raise UpdateError("Обновление не новее установленной версии.")
    log(f"Загружаем и проверяем официальный релиз {release.version}…")
    payload, _ = download_release(release)
    local_manifest = root / MANIFEST
    if local_manifest.exists():
        if _is_link(local_manifest):
            raise UpdateError("Manifest не должен быть ссылкой.")
        old_files = _manifest(local_manifest.read_bytes(), current)
    else:
        # GitHub's automatic Source code ZIP has no generated manifest asset.
        log("Проверяем состав исходной версии по её официальному релизу…")
        _, old_files = download_release(Release(current))
    original = _inventory(root)
    for path, digest in old_files.items():
        if original.get(path) != ("file", digest):
            raise UpdateError(
                "Файлы программы изменены или удалены. Автообновление остановлено; сохраните свои правки при ручном обновлении."
            )
    kept = {
        path: value
        for path, value in original.items()
        if path not in old_files and path != MANIFEST and not _generated(path)
    }
    # Directories are merged, but any file/name-prefix collision must abort.
    names = {path.casefold(): value[0] for path, value in kept.items()}
    for path in payload:
        parts = PurePosixPath(path).parts
        if names.get(path.casefold()) is not None or any(
            names.get(PurePosixPath(*parts[:index]).as_posix().casefold())
            in {"file", "link"}
            for index in range(1, len(parts))
        ):
            raise UpdateError(
                "Новый файл программы конфликтует с пользовательским файлом. Выполните ручное обновление."
            )
    total = sum(
        (root / path).stat().st_size
        for path, value in original.items()
        if value[0] == "file"
    )
    if shutil.disk_usage(root.parent).free < total * 2 + MAX_EXPANDED:
        raise UpdateError(
            "Недостаточно места для полной резервной копии и новой версии."
        )
    backup = staging = None
    verified_backup = False
    try:
        log("Создаём полную резервную копию и сверяем каждый файл…")
        backup = _private_directory(root.parent, root.name + "-backup-")
        _copy_inventory(root, backup, original)
        if _inventory(backup) != original or _inventory(root) != original:
            raise UpdateError(
                "Файлы изменились во время копирования. Закройте другие экземпляры программы и повторите обновление."
            )
        verified_backup = True
        log(f"Проверенная резервная копия: {backup}")
        staging = _private_directory(root.parent, root.name + "-updating-")
        _copy_inventory(backup, staging, kept)
        for relative, content in payload.items():
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(content)
        if os.name != "nt":
            (staging / "run.sh").chmod(0o700)
        staged = _inventory(staging)
        for path, value in kept.items():
            if staged.get(path) != value:
                raise UpdateError(
                    "Не удалось подтвердить сохранность пользовательских файлов."
                )
        for path, content in payload.items():
            if staged.get(path) != ("file", hashlib.sha256(content).hexdigest()):
                raise UpdateError("Не удалось проверить установленный файл программы.")
        if _inventory(root) != original:
            raise UpdateError(
                "Исходная папка изменилась во время обновления. Повторите после завершения другой операции."
            )
        destination = (
            root.parent / f"{root.name}-v{release.version}-{uuid.uuid4().hex[:8]}"
        )
        staging.rename(destination)
        staging = None
        return destination, backup
    finally:
        # Only private folders created by this invocation can be removed.
        if staging is not None:
            shutil.rmtree(staging)
        if backup is not None and not verified_backup:
            shutil.rmtree(backup)


def offer_update(
    current: str,
    *,
    confirm,
    root: Path | None = None,
    explicit: bool = False,
    log=print,
) -> bool:
    """True means an update was installed: stop this old CLI before any SSH work."""
    release, checked = check_bounded(current)
    if not checked:
        if explicit:
            raise UpdateError(
                "Проверить обновления сейчас не удалось. Текущая версия остаётся доступной."
            )
        log(
            "Проверить обновления сейчас не удалось. Текущая версия остаётся доступной."
        )
        return False
    if release is None:
        if explicit:
            log(f"Установлена актуальная стабильная версия {current}.")
        return False
    log(f"Доступно обновление {current} → {release.version}: {release.page}")
    log(
        "Установщик подготовит отдельную папку и полную резервную копию. Настройки, UUID и ссылки сохранятся; VPS не изменяются."
    )
    if not confirm("Установить обновление сейчас?"):
        return False
    try:
        destination, backup = install_release(
            root or Path(__file__).resolve().parent.parent, current, release, log=log
        )
    except UpdateError as exc:
        if explicit:
            raise
        log(f"Обновление не установлено: {exc}")
        log(
            "Исходная папка не изменена. Инструкция ручного обновления: " + RELEASES_URL
        )
        return False
    except Exception:
        if explicit:
            raise UpdateError(
                "Обновление не установлено. Исходная папка не изменена."
            ) from None
        log(
            "Обновление не установлено. Исходная папка не изменена; продолжайте работу в текущей версии. Для ручного обновления см. "
            + RELEASES_URL
        )
        return False
    log(f"Новая версия: {destination}")
    log(f"Резервная копия: {backup}")
    launcher = "run.cmd" if os.name == "nt" else "run.sh"
    log(
        f"Закройте старое окно и запустите {destination / launcher}. Старую папку пока сохраните."
    )
    log("Текущий мастер завершён. Настройка VPS и перевыпуск ссылок не запускались.")
    return True
