"""Interactive CLI; SSH passwords exist only in process memory."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import re
import socket
import sys
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
from .render import client_xray, extra, nginx_config, origin_xray, exit_xray, vless_uri


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
    path: Path, credentials: dict | None = None, *, replace_existing: bool = False
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
        "origin": ask_server(
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
    if path.exists():
        index = 1
        backup = path.with_name(f"{path.stem}.backup-{index}{path.suffix}")
        while backup.exists() or backup.is_symlink():
            index += 1
            backup = path.with_name(f"{path.stem}.backup-{index}{path.suffix}")
        # Preserve the old file byte-for-byte, including BOM and line endings.
        import os

        with os.fdopen(
            os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as f:
            f.write(path.read_bytes())
        print(f"Прежняя конфигурация сохранена: {backup}")
    write_private(path, json.dumps(c, indent=2, ensure_ascii=False) + "\n")
    print(f"Параметры сохранены: {path}. Файл содержит UUID доступа, но не SSH-пароли.")
    return c


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
        if expected not in addresses:
            raise ValueError(f"DNS {host} не указывает на заданный IP {expected}")
        # A separately routable IPv6 may belong to the same VPS; never silently ignore it.
        unexpected = addresses - {expected}
        if unexpected:
            raise ValueError(
                f"DNS {host} содержит дополнительные A/AAAA ({', '.join(map(str, unexpected))}). Для предсказуемого ACME оставьте только адрес VPS, указанный в конфигурации"
            )
        print(f"DNS {host}: OK")


def write_connection(
    c: dict, directory: Path, verified: bool, checks: dict | None = None
) -> None:
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
    clients_dir = directory / "clients"
    if clients_dir.is_symlink():
        raise ValueError("Папка clients не должна быть символической ссылкой")
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
    write_private(
        directory / "status.json",
        json.dumps(
            {
                "endpoint_verified": verified,
                "vless_tunnel_verified": False,
                "note": "Endpoint check tests TLS and OPTIONS body forwarding, not authenticated VLESS tunnel or speed.",
                "checks": checks,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
    )


def check(c: dict) -> dict:
    from .health import check_endpoint

    checks = {}
    for name in ("origin", "cdn"):
        host = c[f"{name}_domain"]
        print(f"Проверка HTTPS + OPTIONS с телом: {host} ...", flush=True)
        result = check_endpoint(host, max_bytes=1000000)
        checks[name] = result
        print("  OK" if result["ok"] else "  ОШИБКА: " + "; ".join(result["errors"]))
    return checks


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


def deploy(c: dict, args: argparse.Namespace, credentials: dict | None = None) -> int:
    from .remote import deploy_server

    credentials = credentials if credentials is not None else {}
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
            )
        except Exception as exc:
            raise RuntimeError(redact(str(exc), credentials)) from None
    checks = check(c)
    verified = all(item["ok"] for item in checks.values())
    write_connection(c, args.output, verified, checks)
    if verified:
        print(
            "\nVPS настроен; TLS и передача OPTIONS через CDN проверены. VLESS-туннель и скорость проверьте клиентом."
        )
        for index in range(len(c.get("uuids", [c["uuid"]]))):
            print(vless_uri(c, index=index))
    else:
        print(
            "\nVPS настроен, но проверка endpoint не пройдена. Проверьте CDN/DNS и повторите команду check. Работоспособность ссылки пока не подтверждена."
        )
    print(
        f"Ссылка, XHTTP extra, полный клиентский конфиг и статус: {args.output.resolve()}"
    )
    return 0 if verified else 2


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
    print(f"План без SSH и изменений на серверах: {directory.resolve()}")


def existing_action(path: Path) -> str:
    print(f"Найдена сохранённая конфигурация: {path}")
    print("1 — Продолжить установку с сохранёнными настройками и UUID")
    print("2 — Настроить заново (прежний файл сохранится в резервной копии)")
    print("3 — Выход")
    while True:
        choice = ask("Выберите действие", "1")
        if choice in {"1", "2", "3"}:
            return choice
        print("Введите 1, 2 или 3.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VLESS XHTTP TLS: настройка VPS под существующий CDN"
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["wizard", "deploy", "plan", "check", "link"],
        default="wizard",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, default=Path("deployment.json"))
    parser.add_argument("--output", type=Path, default=Path("result"))
    parser.add_argument("--known-hosts", type=Path, default=Path("known_hosts"))
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Пропустить обзор установки; проверка нового SSH-ключа всё равно интерактивна",
    )
    args = parser.parse_args(argv)
    credentials: dict = {}
    try:
        if args.command == "wizard":
            action = existing_action(args.config) if args.config.exists() else "2"
            if action == "3":
                return 0
            c = (
                load(args.config)
                if action == "1"
                else wizard(
                    args.config, credentials, replace_existing=args.config.exists()
                )
            )
        else:
            c = load(args.config)
        if args.command in {"wizard", "deploy"}:
            return deploy(c, args, credentials)
        if args.command == "plan":
            plan(c, args.output)
        elif args.command == "check":
            checks = check(c)
            verified = all(x["ok"] for x in checks.values())
            write_connection(c, args.output, verified, checks)
            return 0 if verified else 2
        elif args.command == "link":
            write_connection(c, args.output, False)
            print("Ссылка сформирована без проверки доступности:")
            for index in range(len(c.get("uuids", [c["uuid"]]))):
                print(vless_uri(c, index=index))
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
