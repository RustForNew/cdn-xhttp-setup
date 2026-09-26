"""Strict, secret-free deployment specifications."""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
import uuid
from pathlib import Path

XRAY_VERSION = "26.5.9"
DEFAULT_PATH = "/api-test"


def domain(value: str) -> str:
    value = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or "." not in value:
        raise ValueError("Укажите полное доменное имя без https:// и пути")
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("Некорректное доменное имя")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Требуется домен, а не IP")


def server(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) - {"host", "user", "port"}:
        raise ValueError(
            "Сервер должен содержать только host, user, port; пароль не сохраняется"
        )
    host = str(ipaddress.ip_address(value["host"]))
    user = value.get("user", "root")
    port = value.get("port", 22)
    if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ValueError("Некорректный SSH login")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("SSH port должен быть от 1 до 65535")
    return {"host": host, "user": user, "port": port}


def certificate_email(value: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value
        )
        or len(value) > 254
    ):
        raise ValueError("Укажите email для Let's Encrypt")
    return value


def connection_name(value: str) -> str:
    if not isinstance(value, str) or any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value
    ):
        raise ValueError("Название должно быть строкой без управляющих символов")
    value = value.strip()
    if not 1 <= len(value) <= 80:
        raise ValueError("Название должно содержать от 1 до 80 символов")
    return value


def validate(value: dict) -> dict:
    allowed = {
        "schema",
        "origin",
        "origin_domain",
        "cdn_domain",
        "connect_address",
        "email",
        "exit",
        "exit_domain",
        "uuid",
        "uuids",
        "name",
        "path",
        "padding_key",
        "profile",
        "xray_version",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError(
            "Неизвестные поля конфигурации (пароли в JSON не поддерживаются)"
        )
    c = dict(value)
    if c.get("schema", 1) != 1:
        raise ValueError("Неподдерживаемая версия конфигурации")
    c["schema"] = 1
    c["origin"] = server(c["origin"])
    for key in ("origin_domain", "cdn_domain"):
        c[key] = domain(c[key])
    if "connect_address" in c:
        value = c["connect_address"]
        if not isinstance(value, str) or "%" in value:
            raise ValueError(
                "connect_address должен быть публичным IP без зоны интерфейса"
            )
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                "connect_address должен быть публичным IPv4 или IPv6"
            ) from exc
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError("connect_address должен быть публичным IPv4 или IPv6")
        c["connect_address"] = str(address)
    if c["origin_domain"] == c["cdn_domain"]:
        raise ValueError("Origin и CDN должны иметь разные домены")
    c["email"] = certificate_email(c.get("email", ""))
    c["name"] = connection_name(c.get("name", "CDN XHTTP"))
    values = c.get("uuids", [c.get("uuid")])
    if not isinstance(values, list) or not 1 <= len(values) <= 1000:
        raise ValueError("uuids должен содержать от 1 до 1000 уникальных UUID")
    if any(not isinstance(item, str) for item in values):
        raise ValueError("Каждый UUID должен быть строкой")
    try:
        c["uuids"] = [str(uuid.UUID(item)) for item in values]
        primary = str(uuid.UUID(c["uuid"])) if "uuid" in c else c["uuids"][0]
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("Некорректный UUID") from exc
    if len(set(c["uuids"])) != len(c["uuids"]):
        raise ValueError("Каждая ссылка должна иметь отдельный UUID; найдены дубликаты")
    if primary != c["uuids"][0]:
        raise ValueError("uuid должен совпадать с первым элементом uuids")
    c["uuid"] = primary
    c["path"] = c.get("path", DEFAULT_PATH)
    if (
        not isinstance(c["path"], str)
        or not re.fullmatch(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", c["path"])
        or len(c["path"]) > 120
        or c["path"] == "/cdn-check"
    ):
        raise ValueError(
            "XHTTP path: /name[/name], латиница, цифры, дефис и подчёркивание; /cdn-check занят"
        )
    c["padding_key"] = c.get("padding_key", "dc")
    if not isinstance(c["padding_key"], str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,32}", c["padding_key"]
    ):
        raise ValueError("Некорректный padding_key")
    c["profile"] = c.get("profile", "fast")
    if c["profile"] not in {"fast", "original"}:
        raise ValueError("profile должен быть fast или original")
    c["xray_version"] = c.get("xray_version", XRAY_VERSION)
    if c["xray_version"] != XRAY_VERSION:
        raise ValueError(f"Эта версия установщика проверена с Xray {XRAY_VERSION}")
    c["exit"] = server(c["exit"]) if c.get("exit") else None
    if c["exit"]:
        c["exit_domain"] = domain(c["exit_domain"])
        if c["exit"]["host"] == c["origin"]["host"]:
            raise ValueError("Для двух серверов нужны разные IP")
        if (
            ipaddress.ip_address(c["exit"]["host"]).version
            != ipaddress.ip_address(c["origin"]["host"]).version
        ):
            raise ValueError(
                "Origin и exit должны использовать одну семью адресов: оба IPv4 или оба IPv6"
            )
        if c["exit_domain"] in {c["origin_domain"], c["cdn_domain"]}:
            raise ValueError("Exit должен иметь отдельный домен")
    else:
        if c.get("exit_domain"):
            raise ValueError("exit_domain задан без exit-сервера")
        c["exit_domain"] = None
    return c


def load(path: Path) -> dict:
    return validate(json.loads(path.read_text(encoding="utf-8-sig")))


def write_private(path: Path, text: str) -> None:
    """Never write SSH secrets. UUID/share links are intentionally local artifacts."""
    import os
    import tempfile

    if path.is_symlink():
        raise ValueError("Файл результата не должен быть символической ссылкой")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
