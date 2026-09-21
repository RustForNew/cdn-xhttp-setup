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
from .config import load, validate, write_private
from .render import client_xray, extra, nginx_config, origin_xray, exit_xray, vless_uri


def ask(label: str, default: str = "") -> str:
    answer = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
    return answer or default


def yes(label: str) -> bool:
    return input(label + " [yes/нет]: ").strip().lower() in {"yes", "да"}


def ask_server(label: str) -> dict:
    print(f"\n{label}")
    return {
        "host": ask("IP сервера"),
        "user": ask("SSH login", "root"),
        "port": int(ask("SSH port", "22")),
    }


def wizard(path: Path) -> dict:
    if path.exists():
        raise ValueError(
            f"Файл {path} уже существует. Используйте deploy --config или другой --config"
        )
    print("CDN XHTTP Setup — готовый CDN + Ubuntu 22.04/24.04")
    name = ask("Название сервера (VLESS-ссылок)", "CDN XHTTP")
    count = int(ask("Количество ссылок с разными UUID (1–1000)", "1"))
    if not 1 <= count <= 1000:
        raise ValueError("Количество ссылок должно быть от 1 до 1000")
    uuids = [str(uuid.uuid4()) for _ in range(count)]
    c = {
        "name": name,
        "uuids": uuids,
        "origin": ask_server("Origin (единственный сервер в режиме 1 VPS)"),
        "cdn_domain": ask("CDN-домен клиентов"),
        "origin_domain": ask("Origin-домен"),
        "email": ask("Email для выпуска сертификата Let's Encrypt"),
        "uuid": uuids[0],
        "exit": None,
    }
    if yes("Использовать отдельный выходной сервер?"):
        c["exit"] = ask_server("Exit")
        c["exit_domain"] = ask("Exit-домен для TLS")
    c["profile"] = ask("Профиль отправки: fast (5 мс) / original (30 мс)", "fast")
    c["path"] = ask("XHTTP path", "/api-test")
    c = validate(c)
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


def deploy(c: dict, args: argparse.Namespace) -> int:
    from .remote import deploy_server

    print(
        f"Режим: {'2 VPS' if c.get('exit') else '1 VPS'}; origin={c['origin']['host']}; CDN={c['cdn_domain']}; профиль={c['profile']}"
    )
    print(
        "Будут установлены Xray, Certbot и службы проекта; на origin — Nginx. Нужен выделенный VPS без посторонних сайтов на 80/443."
    )
    dns_preflight(c)
    if not args.yes and not yes(
        "Начать настройку указанных VPS и выпуск сертификатов Let's Encrypt?"
    ):
        print("Установка отменена. Конфигурация сохранена.")
        return 0
    # Passwords are requested per host, after the review. Agent/key auth works with blank password.
    for role in ("exit", "origin"):
        s = c.get(role)
        if not s:
            continue
        password = (
            getpass.getpass(
                f"SSH пароль {s['user']}@{s['host']} (Enter: SSH agent/ключ): "
            )
            or None
        )
        sudo_password = None
        if s["user"] != "root":
            sudo_password = getpass.getpass("Пароль sudo (Enter: NOPASSWD): ") or None
        try:
            deploy_server(
                c,
                role,
                password=password,
                sudo_password=sudo_password,
                known_hosts=args.known_hosts,
                confirm_host=lambda message: yes(
                    message
                    + "\nСверьте fingerprint с консолью VPS. Доверять этому ключу?"
                ),
                log=lambda text: print(text, flush=True),
            )
        finally:
            password = sudo_password = None
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
    try:
        c = wizard(args.config) if args.command == "wizard" else load(args.config)
        if args.command in {"wizard", "deploy"}:
            return deploy(c, args)
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
            "\nОперация прервана. Повторный deploy использует тот же UUID из конфигурации.",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        # Do not print tracebacks or connection object reprs containing credentials.
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
