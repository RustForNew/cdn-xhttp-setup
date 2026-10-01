"""Interactive CLI; SSH passwords exist only in process memory."""

from __future__ import annotations

import argparse
import copy
import getpass
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import uuid
from pathlib import Path

from . import __version__
from .config import (
    DEFAULT_PATH,
    certificate_email,
    connection_name,
    domain,
    load,
    server,
    validate,
    write_private,
)
from .render import client_xray, exit_xray, extra, nginx_config, origin_xray, vless_uri


def ask(label: str, default: str = "") -> str:
    answer = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
    return answer or default


def yes(label: str, default: bool = False) -> bool:
    while True:
        choice = (
            input(f"{label} [Y/N, Enter = {'Y' if default else 'N'}]: ").strip().lower()
        )
        if not choice:
            return default
        if choice in {"y", "yes", "да", "д"}:
            return True
        if choice in {"n", "no", "нет", "н"}:
            return False
        print("Введите Y (да) или N (нет).")


def ask_validated(label: str, validator, default: str = ""):
    while True:
        try:
            return validator(ask(label, default))
        except (ValueError, UnicodeError) as exc:
            print(f"{exc}. Попробуйте ещё раз.")


def number(value: str, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except ValueError:
        raise ValueError(f"Введите целое число от {minimum} до {maximum}") from None
    if not minimum <= result <= maximum:
        raise ValueError(f"Введите целое число от {minimum} до {maximum}")
    return result


def ask_credentials(s: dict) -> dict:
    print("Пароль вводится скрыто: символы не отображаются и не сохраняются в файл.")
    credentials = {
        "password": getpass.getpass(
            f"SSH-пароль {s['user']}@{s['host']} (Enter — использовать SSH-ключ): "
        )
        or None,
        "sudo_password": None,
    }
    if s["user"] != "root":
        credentials["sudo_password"] = (
            getpass.getpass("Пароль sudo (Enter — sudo без пароля): ") or None
        )
    return credentials


def ask_server(
    label: str,
    credentials: dict | None = None,
    role: str = "origin",
    origin: dict | None = None,
) -> dict:
    print(f"\n{label}")

    def address(value):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Укажите корректный IP-адрес сервера") from None
        if origin:
            other = ipaddress.ip_address(origin["host"])
            if ip == other:
                raise ValueError("Для моста нужны два разных сервера")
            if ip.version != other.version:
                raise ValueError("Оба сервера должны использовать IPv4 или оба IPv6")
        return str(ip)

    s = {"host": ask_validated("IP сервера", address)}
    s["user"] = ask_validated(
        "SSH-логин", lambda value: server({**s, "user": value})["user"], "root"
    )
    s["port"] = ask_validated("SSH-порт", lambda value: number(value, 1, 65535), "22")
    if credentials is not None:
        credentials[role] = ask_credentials(s)
    return s


def ask_domain(label: str, used: tuple[str, ...] = ()) -> str:
    def unique(value):
        result = domain(value)
        if result in used:
            raise ValueError("Для этого назначения нужен отдельный домен")
        return result

    return ask_validated(label, unique)


def wizard(
    path: Path,
    credentials: dict | None = None,
    *,
    replace_existing: bool = False,
    origin: dict | None = None,
) -> dict:
    if path.is_symlink():
        raise ValueError("Файл конфигурации не должен быть символической ссылкой")
    if path.exists() and not replace_existing:
        raise ValueError(
            f"Файл {path} уже существует. Используйте deploy --config или другой --config"
        )
    print("CDN XHTTP Setup — готовый CDN + Ubuntu 22.04/24.04")
    print("Без моста нужен один VPS. С мостом — входной VPS и отдельный выходной VPS.")
    bridge = yes("Использовать мост из двух серверов?")
    c = {
        "origin": origin
        or ask_server(
            "Входной сервер — принимает подключения от CDN" if bridge else "Сервер",
            credentials,
            "origin",
        ),
        "exit": None,
    }
    c["origin_domain"] = ask_domain("Домен этого сервера (origin)")
    if bridge:
        c["exit"] = ask_server(
            "Выходной сервер — через него будет выход в интернет",
            credentials,
            "exit",
            origin=c["origin"],
        )
        c["exit_domain"] = ask_domain("Домен выходного сервера", (c["origin_domain"],))
    print("\nCDN и ссылки для пользователей")
    c["cdn_domain"] = ask_domain(
        "CDN-домен клиентов", (c["origin_domain"], c.get("exit_domain", ""))
    )
    c["email"] = ask_validated(
        "Email для выпуска сертификата Let's Encrypt", certificate_email
    )
    c["name"] = ask_validated(
        "Название сервера (VLESS-ссылок)", connection_name, "CDN XHTTP"
    )
    count = ask_validated(
        "Количество ссылок с разными UUID (1–1000)",
        lambda value: number(value, 1, 1000),
        "1",
    )
    c["uuids"] = [str(uuid.uuid4()) for _ in range(count)]
    c["uuid"] = c["uuids"][0]
    c["profile"] = "fast"
    c["path"] = DEFAULT_PATH
    c = validate(c)
    save_configuration(path, c, backup=path.exists())
    print(f"Параметры сохранены: {path}. Файл содержит UUID доступа, но не SSH-пароли.")
    return c


def save_configuration(path: Path, c: dict, *, backup: bool = False) -> None:
    """Replace a validated local spec atomically, preserving its text encoding."""
    if path.is_symlink():
        raise ValueError("Файл конфигурации не должен быть символической ссылкой")
    c = validate(c)
    previous = path.read_bytes() if path.exists() else b""
    newline = "\r\n" if b"\r\n" in previous else "\n"
    payload = (
        (json.dumps(c, indent=2, ensure_ascii=False) + "\n")
        .replace("\n", newline)
        .encode("utf-8")
    )
    if previous.startswith(b"\xef\xbb\xbf"):
        payload = b"\xef\xbb\xbf" + payload
    if previous == payload:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if backup and path.exists():
        index = 1
        backup_path = path.with_name(f"{path.stem}.backup-{index}{path.suffix}")
        while backup_path.exists() or backup_path.is_symlink():
            index += 1
            backup_path = path.with_name(f"{path.stem}.backup-{index}{path.suffix}")
        with os.fdopen(
            os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as handle:
            handle.write(previous)
        print(f"Прежняя конфигурация сохранена: {backup_path}")
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


# VPN clients in fake-ip or TUN mode answer every name from this benchmark
# range (RFC 2544) and resolve the real address themselves later.
FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")


def dns_preflight(c: dict) -> None:
    for role in ("origin", "exit"):
        if not c.get(role):
            continue
        host = c[f"{role}_domain"]
        expected = ipaddress.ip_address(c[role]["host"])
        try:
            addresses = {
                ipaddress.ip_address(x[4][0])
                for x in socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
            }
        except OSError as exc:
            raise ValueError(
                f"DNS {host} не разрешается. Создайте A/AAAA-запись до установки"
            ) from exc
        fake = sorted(
            str(address)
            for address in addresses
            if address.version == 4 and address in FAKE_IP_NETWORK
        )
        if fake and expected not in FAKE_IP_NETWORK:
            # The VPS checks the real A/AAAA records again before ACME.
            print(
                f"DNS {host}: локальный резолвер вернул {', '.join(fake)} из 198.18.0.0/15 — так отвечает VPN в режиме fake-ip/TUN. "
                "Проверить запись с этого компьютера нельзя; VPS сверит A/AAAA со своим IP перед выпуском сертификата."
            )
            continue
        if expected not in addresses:
            raise ValueError(f"DNS {host} не указывает на заданный IP {expected}")
        # A separately routable IPv6 may belong to the same VPS; never silently ignore it.
        unexpected = addresses - {expected}
        if unexpected:
            raise ValueError(
                f"DNS {host} содержит дополнительные A/AAAA ({', '.join(map(str, unexpected))}). Для предсказуемого ACME оставьте только адрес VPS, указанный в конфигурации"
            )
        print(f"DNS {host}: OK")


NOTE_PREVIEW = "Offline preview; authenticated VLESS tunnel is not verified."
NOTE_PENDING = "Links issued; the local connection check has not finished."
NOTE_VERIFIED = "Authenticated VLESS/XHTTP transfer through the CDN domain verified from this computer; availability can change."
NOTE_UNVERIFIED = "Links issued; the local connection check did not confirm the tunnel from this computer (informational only)."


def write_status(
    directory: Path,
    *,
    endpoint_verified: bool,
    vless_verified: bool,
    note: str,
    checks: dict | list | None = None,
) -> None:
    write_private(
        directory / "status.json",
        json.dumps(
            {
                "endpoint_verified": endpoint_verified,
                "vless_tunnel_verified": vless_verified,
                "note": note,
                "checks": checks,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
    )


def write_connection(
    c: dict,
    directory: Path,
    verified: bool,
    checks: dict | list | None = None,
    *,
    vless_verified: bool = False,
    note: str | None = None,
) -> None:
    if directory.is_symlink():
        raise ValueError("Папка результата не должна быть символической ссылкой")
    clients_dir = directory / "clients"
    if clients_dir.is_symlink():
        raise ValueError("Папка clients не должна быть символической ссылкой")
    directory.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        directory.chmod(0o700)
    count = len(c.get("uuids", [c["uuid"]]))
    write_private(
        directory / "vless.txt",
        "\n".join(vless_uri(c, index=i) for i in range(count)) + "\n",
    )
    write_private(directory / "xhttp-extra.json", json.dumps(extra(c), indent=2) + "\n")
    write_private(
        directory / "client.json", json.dumps(client_xray(c), indent=2) + "\n"
    )
    expected_clients = (
        {f"client-{index + 1:03d}.json" for index in range(count)}
        if count > 1
        else set()
    )
    if clients_dir.exists():
        for previous in clients_dir.iterdir():
            if (
                re.fullmatch(r"client-[0-9]+\.json", previous.name)
                and previous.name not in expected_clients
            ):
                if previous.is_file() or previous.is_symlink():
                    previous.unlink()
    if count > 1:
        clients_dir.mkdir(exist_ok=True)
        if sys.platform != "win32":
            clients_dir.chmod(0o700)
        for index in range(count):
            write_private(
                clients_dir / f"client-{index + 1:03d}.json",
                json.dumps(client_xray(c, index=index), indent=2) + "\n",
            )
    if note is None:
        note = NOTE_VERIFIED if vless_verified else NOTE_PREVIEW
    write_status(
        directory,
        endpoint_verified=verified,
        vless_verified=vless_verified,
        note=note,
        checks=checks,
    )


def check(c: dict) -> dict:
    """Informational local check; network failures are results, not errors."""
    from .verify import verify_connection

    return verify_connection(c, log=lambda message: print(message, flush=True))


def issue_connections(
    c: dict, args: argparse.Namespace, *, strict: bool = False
) -> int:
    """Always issue links for the current settings, then check them locally.

    The check only informs: it never withholds or replaces the links. With
    strict (the ``check`` command) an unconfirmed tunnel returns exit code 2.
    """
    c = validate(c)
    previous_local = load(args.config) if args.config.exists() else None
    write_connection(c, args.output, False, note=NOTE_PENDING)
    save_configuration(
        args.config,
        c,
        backup=previous_local is not None and previous_local != c,
    )
    print(f"Адрес подключения в ссылках: {c['cdn_domain']}:443 (CDN-домен).")
    for index in range(len(c["uuids"])):
        print(vless_uri(c, index=index))
    print(f"Ссылки и клиентские конфиги: {args.output.resolve()}")
    print(
        "Проверяем подключение с этого компьютера. Проверка только информирует: ссылки уже выданы."
    )
    try:
        result = check(c)
    except Exception as exc:
        # Never let an unexpected check failure turn issued links into an error.
        result = {
            "endpoint_verified": False,
            "vless_tunnel_verified": False,
            "checks": [
                {"name": "verification", "ok": False, "error": type(exc).__name__}
            ],
        }
    verified = result.get("vless_tunnel_verified") is True
    write_status(
        args.output,
        endpoint_verified=result.get("endpoint_verified") is True,
        vless_verified=verified,
        note=NOTE_VERIFIED if verified else NOTE_UNVERIFIED,
        checks=result.get("checks"),
    )
    if verified:
        print("Полный VLESS-путь через CDN-домен подтверждён с этого компьютера.")
    else:
        print(
            "Предупреждение: проверка с этого компьютера не подтвердила туннель. Ссылки выданы; "
            f"причина — в {args.output / 'status.json'}. Проверьте подключение в клиентском приложении."
        )
    return 2 if strict and not verified else 0


def show_summary(c: dict) -> None:
    print(
        f"\nРежим: {'мост, 2 сервера' if c.get('exit') else 'один сервер, без моста'}"
    )
    for role, label in (
        ("origin", "Входной сервер" if c.get("exit") else "Сервер"),
        ("exit", "Выходной сервер"),
    ):
        if c.get(role):
            s = c[role]
            print(
                f"{label}: {s['user']}@{s['host']}:{s['port']} — {c[role + '_domain']}"
            )
    print(f"CDN-домен: {c['cdn_domain']}")
    print(f"Название: {c['name']}; ссылок: {len(c['uuids'])}")


def redact(text: str, credentials: dict) -> str:
    for secrets in credentials.values():
        for value in secrets.values():
            if value:
                text = text.replace(value, "[скрыто]")
    return text


def pending_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}.pending{path.suffix}")


def read_pending(path: Path) -> tuple[dict, dict] | None:
    pending = pending_path(path)
    if pending.is_symlink():
        raise ValueError(
            "Файл незавершённого изменения не должен быть символической ссылкой"
        )
    if not pending.exists():
        return None
    value = json.loads(pending.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or set(value) != {"target", "previous"}:
        raise ValueError("Некорректный файл незавершённого изменения")
    return validate(value["target"]), validate(value["previous"])


def stage_pending(path: Path, c: dict, previous: dict) -> None:
    target, old = validate(c), validate(previous)
    existing = read_pending(path)
    if existing is not None and existing != (target, old):
        raise ValueError(
            "Есть другое незавершённое изменение. Продолжите его через пункт 6 меню управления"
        )
    if existing is None:
        write_private(
            pending_path(path),
            json.dumps(
                {"target": target, "previous": old}, indent=2, ensure_ascii=False
            )
            + "\n",
        )


def check_topology(c: dict, previous: dict | None, config_path: Path) -> None:
    """Render every role offline; refuse a change that cannot be applied."""
    from .remote import render_bootstrap

    try:
        for role in ("exit", "origin"):
            if c.get(role):
                if previous is None:
                    render_bootstrap(c, role)
                else:
                    render_bootstrap(c, role, previous=previous)
    except ValueError as exc:
        reason = f"Изменение нельзя применить: {exc}"
        # Releases up to 0.3.1 staged such a change before this check; offer
        # to discard that stuck pending file, the main settings stay intact.
        try:
            stuck = previous is not None and read_pending(config_path) == (
                validate(c),
                validate(previous),
            )
        except ValueError:
            stuck = False
        if stuck:
            print(f"{reason}.")
            if yes(
                f"Удалить невыполнимое незавершённое изменение {pending_path(config_path)}? Основной файл настроек не изменится"
            ):
                pending_path(config_path).unlink()
                print("Незавершённое изменение удалено.")
        raise ValueError(reason) from None


def deploy(
    c: dict,
    args: argparse.Namespace,
    credentials: dict | None = None,
    *,
    previous: dict | None = None,
) -> int:
    from .remote import deploy_server

    credentials = credentials if credentials is not None else {}
    # Validate the topology before anything is staged: a pending file for a
    # change that can never be rendered would otherwise block the menu.
    check_topology(c, previous, args.config)
    show_summary(c)
    print(
        "Будут установлены Xray, Certbot и службы проекта; на origin — Nginx. Нужен выделенный VPS без посторонних сайтов на 80/443."
    )
    if not args.yes and not yes(
        "Начать настройку указанных VPS и выпуск сертификатов Let's Encrypt?"
    ):
        print(
            "Установка отменена. Запустите программу снова, чтобы продолжить с этими настройками."
        )
        return 0
    # Collect both servers' credentials before changing either VPS.
    for role in ("origin", "exit"):
        if c.get(role) and role not in credentials:
            credentials[role] = ask_credentials(c[role])
    dns_preflight(c)
    if previous is not None:
        stage_pending(args.config, c, previous)
    for role in ("exit", "origin"):
        s = c.get(role)
        if not s:
            continue
        try:
            deploy_server(
                c,
                role,
                password=credentials[role]["password"],
                sudo_password=credentials[role]["sudo_password"],
                known_hosts=args.known_hosts,
                confirm_host=lambda message: yes(
                    message
                    + "\nСверьте fingerprint с консолью VPS. Доверять этому ключу?"
                ),
                log=lambda text: print(redact(text, credentials), flush=True),
                **({"previous": previous} if previous is not None else {}),
            )
        except Exception as exc:
            if previous is not None:
                print(
                    "Изменение выполнено не полностью. Прежний локальный конфиг сохранён; для продолжения с теми же UUID выберите пункт 6 меню управления."
                )
            raise RuntimeError(redact(str(exc), credentials)) from None
    # Server state is now authoritative even when the following network check fails.
    save_configuration(args.config, c, backup=previous is not None)
    if previous is not None:
        pending_path(args.config).unlink()
    print("\nСерверные настройки применены. Выдаём ссылки.")
    return issue_connections(c, args)


def plan(c: dict, directory: Path) -> None:
    from .remote import render_bootstrap

    directory.mkdir(parents=True, exist_ok=True)
    for role in ("origin", "exit"):
        if not c.get(role):
            continue
        write_private(directory / f"{role}-install.sh", render_bootstrap(c, role))
        write_private(
            directory / f"{role}-xray.json",
            json.dumps(origin_xray(c) if role == "origin" else exit_xray(c), indent=2)
            + "\n",
        )
    write_private(directory / "nginx.conf", nginx_config(c))
    write_connection(c, directory, False)
    print(
        f"Непроверенный план без SSH и изменений на серверах: {directory.resolve()}. Ссылки в плане — только для просмотра."
    )


def existing_action(path: Path) -> str:
    print(f"Управление настройками: {path}")
    print("1 — Выдать ссылки с прежними UUID и проверить подключение")
    print("2 — Изменить количество доступов (UUID)")
    print("3 — Изменить домены, название и параметры подключения")
    print("4 — Повторить установку с сохранёнными настройками")
    print("5 — Подключиться к другому origin по SSH")
    if pending_path(path).exists():
        print("6 — Продолжить незавершённое изменение с прежними UUID")
    print("0 — Выход")
    while True:
        choice = ask("Выберите действие", "1")
        resumable = pending_path(path).exists()
        if choice in {"0", "1", "2", "3", "4", "5"} or (choice == "6" and resumable):
            return choice
        print(f"Введите число от 0 до {6 if resumable else 5}.")


def recover(
    server_spec: dict, args: argparse.Namespace, credentials: dict
) -> dict | None:
    from .remote import recover_config

    if "origin" not in credentials:
        credentials["origin"] = ask_credentials(server_spec)
    return recover_config(
        server_spec,
        password=credentials["origin"]["password"],
        sudo_password=credentials["origin"]["sudo_password"],
        known_hosts=args.known_hosts,
        confirm_host=lambda message: yes(
            message + "\nСверьте fingerprint с консолью VPS. Доверять этому ключу?"
        ),
    )


def complete_recovered(raw: dict, local: dict | None = None) -> dict:
    c = copy.deepcopy(raw)
    legacy = c.pop("_recovered_legacy", False)
    if c.pop("_server_outdated", False):
        print(
            "На сервере установлена схема XHTTP прежней версии программы (данные в теле OPTIONS); Yandex CDN отклоняет такие запросы. "
            "Ссылки этой версии передают данные в заголовках и заработают после повторной установки: пункт 4 меню или команда deploy. "
            "UUID и настройки сохраняются."
        )
    if legacy:
        print(
            "Найдена установка старой версии. UUID и серверные параметры восстановлены; email, название и профиль в старой серверной копии не сохранялись."
        )
        c["email"] = ask_validated(
            "Email для выпуска сертификата Let's Encrypt",
            certificate_email,
            local["email"] if local else "",
        )
        c["name"] = local["name"] if local else "CDN XHTTP"
        c["profile"] = local["profile"] if local else "fast"
        print(
            f"Профиль: {c['profile']}. Его и название можно изменить в меню параметров."
        )
        if c.get("exit"):
            saved = local.get("exit") if local else None
            defaults = (
                saved if saved and saved["host"] == c["exit"]["host"] else c["exit"]
            )
            print(f"Проверьте SSH-доступ к восстановленному exit {c['exit']['host']}.")
            c["exit"]["user"] = ask_validated(
                "SSH-логин exit",
                lambda value: server({**c["exit"], "user": value})["user"],
                defaults.get("user", "root"),
            )
            c["exit"]["port"] = ask_validated(
                "SSH-порт exit",
                lambda value: number(value, 1, 65535),
                str(defaults.get("port", 22)),
            )
    return validate(c)


def refresh_config(c: dict, args: argparse.Namespace, credentials: dict) -> dict:
    """Use the authorized identities on the server before exporting local links."""
    try:
        raw = recover(c["origin"], args, credentials)
        if raw is None:
            raise ValueError(
                "Установка программы на origin не найдена; список действующих UUID не подтверждён"
            )
        return complete_recovered(raw, c)
    except BaseException:
        # A cancelled SSH read also invalidates this attempt, not the old link files.
        # Never serialize exception text: remote failures may contain credentials.
        try:
            if args.output.is_symlink():
                raise ValueError(
                    "Папка результата не должна быть символической ссылкой"
                )
            write_status(
                args.output,
                endpoint_verified=False,
                vless_verified=False,
                note="Current server configuration could not be read over SSH; no links were issued and earlier connection files, if any, were not replaced.",
            )
        except (OSError, ValueError):
            # Preserve the original failure when the output is not writable.
            pass
        raise


def change_count(c: dict) -> dict:
    updated = copy.deepcopy(c)
    old_count = len(c["uuids"])
    count = ask_validated(
        "Количество доступов (1–1000)",
        lambda value: number(value, 1, 1000),
        str(old_count),
    )
    if count < old_count:
        print(
            f"Будут отозваны последние {old_count - count} доступов: номера {count + 1}–{old_count}. Первые {count} UUID сохранятся."
        )
        if not yes("Применить уменьшение количества доступов?"):
            return c
    updated["uuids"] = c["uuids"][:count] + [
        str(uuid.uuid4()) for _ in range(max(0, count - old_count))
    ]
    updated["uuid"] = updated["uuids"][0]
    return validate(updated)


def change_settings(c: dict) -> dict:
    updated = copy.deepcopy(c)
    print(
        "Enter сохраняет прежнее значение. DNS и ресурс CDN изменяются в панели провайдера отдельно."
    )
    for key, label in (
        ("origin_domain", "Домен origin"),
        ("cdn_domain", "CDN-домен клиентов"),
        ("exit_domain", "Домен exit"),
    ):
        if key == "exit_domain" and not c.get("exit"):
            continue

        def checked_domain(value, field=key):
            normalized = domain(value)
            validate({**updated, field: normalized})
            return normalized

        updated[key] = ask_validated(label, checked_domain, updated[key])
    updated["name"] = ask_validated("Название ссылок", connection_name, updated["name"])
    updated["email"] = ask_validated(
        "Email для сертификата", certificate_email, updated["email"]
    )
    for key, label in (
        ("profile", "Профиль (fast/original)"),
        ("path", "Путь XHTTP"),
        ("padding_key", "Ключ padding"),
    ):

        def checked_field(value, field=key):
            return validate({**updated, field: value})[field]

        updated[key] = ask_validated(label, checked_field, updated[key])
    if any(updated[key] != c[key] for key in ("origin_domain", "cdn_domain")):
        print(
            "Обновите DNS, сертификат CDN и Origin/Host/SNI ресурса CDN под новые домены. Без этого проверка туннеля может не пройти."
        )
    return validate(updated)


def manage(
    c: dict, args: argparse.Namespace, credentials: dict, *, recovered: bool = False
) -> int:
    show_summary(c)
    choice = existing_action(args.config)
    if choice == "0":
        return 0
    if choice == "1":
        current = c if recovered else refresh_config(c, args, credentials)
        return issue_connections(current, args)
    if choice == "6":
        pending = read_pending(args.config)
        if pending is None:
            raise ValueError("Незавершённое изменение не найдено")
        target, previous = pending
        return deploy(target, args, credentials, previous=previous)
    if choice == "5":
        # A different host must not inherit the previous host's password.
        for item in credentials.values():
            item.clear()
        credentials.clear()
        return connect_wizard(args, credentials)
    previous = c if recovered else None
    if not recovered:
        raw = recover(c["origin"], args, credentials)
        if raw is not None:
            previous = complete_recovered(raw, c)
    if choice in {"2", "3"}:
        if previous is None:
            raise ValueError(
                "Установка программы на origin не найдена. Выберите повторную установку для сохранённых настроек"
            )
        c = change_count(previous) if choice == "2" else change_settings(previous)
        if c == previous:
            print("Настройки не изменились.")
            return 0
    elif previous is not None:
        # Reinstall the current server state, never stale local credentials.
        c = previous
    return deploy(c, args, credentials, previous=previous)


def connect_wizard(args: argparse.Namespace, credentials: dict) -> int:
    if read_pending(args.config) is not None:
        raise ValueError(
            "Сначала продолжите незавершённое изменение через пункт 6 или задайте отдельный --config для другого сервера"
        )
    print("CDN XHTTP Setup — подключение к origin и поиск сохранённой установки")
    origin = ask_server("Origin — сервер, принимающий подключения от CDN", credentials)
    raw = recover(origin, args, credentials)
    if raw is not None:
        print("Найдена установка CDN XHTTP Setup. Существующие UUID сохранены.")
        return manage(complete_recovered(raw), args, credentials, recovered=True)
    print("Сохранённая установка не найдена. Настроим новый сервер.")
    c = wizard(
        args.config, credentials, replace_existing=args.config.exists(), origin=origin
    )
    return deploy(c, args, credentials)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VLESS XHTTP TLS: настройка VPS под существующий CDN"
    )
    commands = ["wizard", "manage", "deploy", "plan", "check", "link", "update"]
    parser.add_argument(
        "command",
        nargs="?",
        # repair-edge is a hidden alias of link kept for scripts of 0.2-0.3.
        choices=commands + ["repair-edge"],
        metavar="{" + ",".join(commands) + "}",
        default="wizard",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, default=Path("deployment.json"))
    parser.add_argument("--output", type=Path, default=Path("result"))
    parser.add_argument("--known-hosts", type=Path, default=Path("known_hosts"))
    parser.add_argument(
        "--no-update-check", action="store_true",
        help="Пропустить проверку новой версии при интерактивном запуске",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Пропустить обзор установки; проверка нового SSH-ключа всё равно интерактивна",
    )
    args = parser.parse_args(argv)
    credentials: dict = {}
    try:
        if args.command == "update" or (
            args.command in {"wizard", "manage"}
            and not args.no_update_check and not args.yes
            and sys.stdin.isatty() and sys.stdout.isatty()
        ):
            from .updates import offer_update

            installed = offer_update(__version__, confirm=yes, explicit=args.command == "update")
            if installed or args.command == "update":
                return 0
        if args.command in {"wizard", "manage"}:
            if args.config.exists():
                return manage(load(args.config), args, credentials)
            pending = read_pending(args.config)
            if pending is not None:
                # Recovery from SSH can fail mid-update before a local main spec exists.
                return manage(pending[1], args, credentials)
            return connect_wizard(args, credentials)
        c = load(args.config)
        if args.command == "deploy":
            raw = recover(c["origin"], args, credentials)
            previous = complete_recovered(raw, c) if raw is not None else None
            if previous is not None:
                if previous.get("exit") and c["uuid"] != previous["uuid"]:
                    raise ValueError(
                        "Первый UUID существующего моста должен сохраняться"
                    )
                removed = set(previous["uuids"]) - set(c["uuids"])
                if removed:
                    print(f"Настройки удалят {len(removed)} существующих доступов.")
            return deploy(c, args, credentials, previous=previous)
        if args.command == "plan":
            plan(c, args.output)
        elif args.command in {"check", "link", "repair-edge"}:
            if args.command == "repair-edge":
                print(
                    "Команда repair-edge устарела: подбор адреса CDN больше не нужен, ссылки используют CDN-домен. Выполняем link."
                )
            return issue_connections(
                refresh_config(c, args, credentials),
                args,
                strict=args.command == "check",
            )
        return 0
    except (KeyboardInterrupt, EOFError):
        print(
            "\nОперация прервана. При следующем запуске можно продолжить с сохранённой конфигурацией, если она была создана.",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        # Do not print tracebacks or connection object reprs containing credentials.
        print(f"Ошибка: {redact(str(exc), credentials)}", file=sys.stderr)
        return 1
    finally:
        for secrets in credentials.values():
            secrets.clear()
        credentials.clear()


if __name__ == "__main__":
    raise SystemExit(main())
