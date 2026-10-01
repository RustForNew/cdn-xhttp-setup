"""SSH transport and a deliberately isolated Ubuntu deployment transaction.

The generated script is inspectable before execution. Package installation,
firewall allowances and ACME issuance are not rolled back; application files,
nginx site links and service state are. Existing unrelated services are refused.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import tempfile
import time
from typing import Callable


class RemoteError(RuntimeError):
    """A deployment or SSH connection failed without exposing credentials."""


class RemoteCommandError(RemoteError):
    """The remote command ran and exited with a non-zero status."""

    def __init__(self, status: int):
        super().__init__(
            f"Remote installer exited with status {status}; see the output above"
        )
        self.status = status


XRAY_SERVICE = """[Unit]
Description=CDN XHTTP Xray
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/opt/cdn-xhttp/xray run -config /etc/cdn-xhttp/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0027

[Install]
WantedBy=multi-user.target
"""

HEALTH_SERVICE = """[Unit]
Description=CDN XHTTP body-integrity probe
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/bin/python3 -I /opt/cdn-xhttp/health.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
"""


def _encoded(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _stage(name: str, value: str) -> str:
    return f"printf '%s' '{_encoded(value)}' | base64 -d > \"$STAGING/{name}\"\n"


def _identity(config: dict, role: str) -> str:
    return (
        json.dumps(
            {
                "role": role,
                "domain": config[f"{role}_domain"],
                "cdn_domain": config["cdn_domain"],
            },
            sort_keys=True,
        )
        + "\n"
    )


def _accepted_runtimes(config: dict, role: str) -> list[dict]:
    """Runtime configs that represent ``config``, including earlier releases.

    Releases up to 0.3.1 rendered the origin inbound differently; an existing
    installation must still be recognized when this release updates it.
    """
    from .render import exit_xray, origin_xray, previous_origin_xray

    if role == "exit":
        return [exit_xray(config)]
    return [origin_xray(config), previous_origin_xray(config)]


def render_bootstrap(config: dict, role: str, *, previous: dict | None = None) -> str:
    """Render a root bash script; its contents include the private VLESS UUID."""
    from .config import PREVIOUS_XRAY_VERSIONS, XRAY_VERSION
    from .render import exit_xray, nginx_config, origin_xray

    if role not in {"origin", "exit"}:
        raise ValueError("role must be origin or exit")
    server = config.get(role)
    if not server:
        raise ValueError(f"No {role} server configured")
    domain = config["origin_domain"] if role == "origin" else config.get("exit_domain")
    if not domain:
        raise ValueError("exit_domain is required for an exit server")
    version = config.get("xray_version") or XRAY_VERSION
    if not isinstance(version, str) or not re.fullmatch(
        r"\d{1,4}\.\d{1,2}\.\d{1,2}", version
    ):
        raise ValueError("Invalid Xray version")
    if version in PREVIOUS_XRAY_VERSIONS:
        version = XRAY_VERSION
    # All substitutions are quoted shell words or base64, including values which
    # normal CLI validation has already constrained.
    settings = {
        "ROLE": role,
        "DOMAIN": domain,
        "SERVER_IP": server["host"],
        "ORIGIN_IP": config["origin"]["host"],
        "EMAIL": config["email"],
        "XRAY_VERSION": version,
        "DEFAULT_SSH_PORT": str(server.get("port", 22)),
    }
    identity = _identity(config, role)
    if previous is not None:
        if not previous.get(role) or previous[role]["host"] != server["host"]:
            raise ValueError("An update cannot move an existing role to another server")
        if bool(previous.get("exit")) != bool(config.get("exit")):
            raise ValueError(
                "Changing the deployment topology requires a new installation"
            )
    header = "#!/usr/bin/env bash\nset -Eeuo pipefail\nexport LC_ALL=C\numask 077\n"
    header += "\n".join(
        f"{key}={shlex.quote(value)}" for key, value in settings.items()
    )
    header += "\nIDENTITY=" + shlex.quote(_encoded(identity)) + "\n"
    header += (
        "PREVIOUS_IDENTITY="
        + shlex.quote(_encoded(_identity(previous, role)) if previous else "")
        + "\n"
    )
    # Retries may find the target already applied by this or an earlier release.
    accepted_xray = (
        _accepted_runtimes(previous, role) + _accepted_runtimes(config, role)[1:]
        if previous
        else None
    )
    header += (
        "PREVIOUS_XRAY="
        + shlex.quote(_encoded(json.dumps(accepted_xray)) if previous else "")
        + "\n"
    )
    current_xray = origin_xray(config) if role == "origin" else exit_xray(config)
    header += "CURRENT_XRAY=" + shlex.quote(_encoded(json.dumps(current_xray))) + "\n"
    header += (
        "PREVIOUS_SETUP="
        + shlex.quote(_encoded(json.dumps(previous)) if previous else "")
        + "\n"
    )
    header += "TARGET_SETUP=" + shlex.quote(_encoded(json.dumps(config))) + "\n"
    payload = _stage(
        "config.json",
        json.dumps(
            origin_xray(config) if role == "origin" else exit_xray(config), indent=2
        )
        + "\n",
    )
    payload += _stage("cdn-xhttp.service", XRAY_SERVICE)
    payload += _stage("setup.json", json.dumps(config, indent=2) + "\n")
    if role == "origin":
        from .health import HEALTH_SERVER_SOURCE

        payload += _stage("nginx-http.conf", nginx_config(config, tls=False))
        payload += _stage("nginx-tls.conf", nginx_config(config, tls=True))
        payload += _stage("health.py", HEALTH_SERVER_SOURCE)
        payload += _stage("cdn-xhttp-health.service", HEALTH_SERVICE)
    return header + _PREFLIGHT + payload + _INSTALL


_PREFLIGHT = r"""
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '[cdn-xhttp] %s\n' "$*"; }
[[ "$(id -u)" == 0 ]] || fail "Root or sudo is required."
[[ -f /etc/os-release ]] || fail "Missing OS identity."
. /etc/os-release
[[ "$ID" == ubuntu && ( "$VERSION_ID" == 22.04 || "$VERSION_ID" == 24.04 ) ]] || fail "Only Ubuntu 22.04/24.04 is supported."
[[ -d /run/systemd/system ]] || fail "A running systemd is required."
case "$(uname -m)" in
    x86_64) ARCH=64 ;;
    aarch64|arm64) ARCH=arm64-v8a ;;
    *) fail "Only amd64 and arm64 are supported." ;;
esac
command -v flock >/dev/null || fail "flock is required."
command -v ss >/dev/null || fail "ss (iproute2) is required."
SSH_PORT="${1:-$DEFAULT_SSH_PORT}"
[[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" -ge 1 && "$SSH_PORT" -le 65535 ]] || fail "Invalid SSH port."
exec 9>/run/lock/cdn-xhttp.lock
flock -n 9 || fail "Another cdn-xhttp deployment is running."

OWN_PATHS=(/etc/cdn-xhttp /opt/cdn-xhttp /etc/systemd/system/cdn-xhttp.service)
if [[ "$ROLE" == origin ]]; then
    OWN_PATHS+=(/etc/systemd/system/cdn-xhttp-health.service /etc/nginx/sites-available/cdn-xhttp.conf /etc/nginx/sites-enabled/cdn-xhttp.conf)
fi
OWN_PATHS+=(/etc/letsencrypt/renewal-hooks/deploy/cdn-xhttp.sh)
MANAGED=0
if [[ -f /etc/cdn-xhttp/deployment.json && ! -L /etc/cdn-xhttp/deployment.json ]]; then
    EXPECTED_IDENTITY="${PREVIOUS_IDENTITY:-$IDENTITY}"
    FOUND_IDENTITY=$(cat /etc/cdn-xhttp/deployment.json)
    [[ "$FOUND_IDENTITY" == "$(printf '%s' "$EXPECTED_IDENTITY" | base64 -d)" || "$FOUND_IDENTITY" == "$(printf '%s' "$IDENTITY" | base64 -d)" ]] || fail "Deployment changed since it was read; reconnect before updating."
    MANAGED=1
fi
[[ -z "$PREVIOUS_IDENTITY" || "$MANAGED" == 1 ]] || fail "The installation to update is missing."
if [[ -n "$PREVIOUS_XRAY" ]]; then
    PREVIOUS_XRAY="$PREVIOUS_XRAY" CURRENT_XRAY="$CURRENT_XRAY" python3 - <<'PY_PREVIOUS'
import base64, json, os, pathlib
p = pathlib.Path('/etc/cdn-xhttp/config.json')
# PREVIOUS_XRAY lists every accepted rendering, including earlier releases.
accepted = json.loads(base64.b64decode(os.environ['PREVIOUS_XRAY']))
accepted.append(json.loads(base64.b64decode(os.environ['CURRENT_XRAY'])))
if p.is_symlink() or json.loads(p.read_text()) not in accepted:
    raise SystemExit('ERROR: Xray configuration changed since it was read; reconnect before updating.')
PY_PREVIOUS
    PREVIOUS_SETUP="$PREVIOUS_SETUP" TARGET_SETUP="$TARGET_SETUP" python3 - <<'PY_SETUP'
import base64, json, os, pathlib
def canonical(value):
    value = dict(value)
    # Local-only or migrated fields: an obsolete edge address and the Xray
    # version pinned by an earlier release are not concurrent changes.
    value.pop('connect_address', None)
    value.pop('xray_version', None)
    for role in ('origin', 'exit'):
        if value.get(role):
            value[role] = {'host': value[role]['host']}
    return value
p = pathlib.Path('/etc/cdn-xhttp/setup.json')
if p.is_symlink():
    raise SystemExit('ERROR: Saved setup is a symlink.')
if p.exists():
    current = canonical(json.loads(p.read_text()))
    expected = [canonical(json.loads(base64.b64decode(os.environ[key]))) for key in ('PREVIOUS_SETUP', 'TARGET_SETUP')]
    if current not in expected:
        raise SystemExit('ERROR: Saved settings changed since they were read; reconnect before updating.')
PY_SETUP
fi
for item in "${OWN_PATHS[@]}"; do
    if [[ "$MANAGED" == 0 && ( -e "$item" || -L "$item" ) ]]; then
        fail "Unmanaged path already exists: $item"
    fi
    if [[ "$item" != /etc/nginx/sites-enabled/cdn-xhttp.conf && -L "$item" ]]; then
        fail "Refusing a symlink at managed path: $item"
    fi
done
[[ ! -L /var/lib/cdn-xhttp && ! -L /var/lib/cdn-xhttp/certificate-owner.json ]] || fail "Unexpected certificate ownership symlink."
[[ ! -L /var/lib/cdn-xhttp/certificates && ! -L "/var/lib/cdn-xhttp/certificates/$DOMAIN.json" ]] || fail "Unexpected certificate record symlink."
if [[ "$MANAGED" == 1 && -e /var/lib/cdn-xhttp/certificate-owner.json ]]; then
    CERT_OWNER=$(cat /var/lib/cdn-xhttp/certificate-owner.json)
    [[ "$CERT_OWNER" == "$(printf '%s' "$IDENTITY" | base64 -d)" || ( -n "$PREVIOUS_IDENTITY" && "$CERT_OWNER" == "$(printf '%s' "$PREVIOUS_IDENTITY" | base64 -d)" ) ]] || fail "Certificate ownership belongs to another deployment."
fi
if [[ "$MANAGED" == 0 && -e "/etc/letsencrypt/live/$DOMAIN" ]]; then
    # Without a managed installation only a certificate this program issued for
    # the same domain and role (an earlier failed attempt) may be reused. Its
    # CDN domain may differ: a retry often corrects exactly that. A marker of a
    # failed first installation without a certificate grants nothing.
    python3 - "$ROLE" "$DOMAIN" <<'PY_FIRST_CERT'
import json, pathlib, sys
role, domain = sys.argv[1:3]
base = pathlib.Path('/var/lib/cdn-xhttp')
def issued_here(path):
    if path.is_symlink() or not path.is_file():
        return False
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    return isinstance(value, dict) and value.get('role') == role and value.get('domain') == domain
if not any(issued_here(path) for path in (base / 'certificates' / (domain + '.json'), base / 'certificate-owner.json')):
    raise SystemExit('ERROR: An existing unmanaged certificate uses this domain; use a fresh VPS or inspect it manually.')
PY_FIRST_CERT
fi
if [[ -n "$PREVIOUS_IDENTITY" && -e "/etc/letsencrypt/live/$DOMAIN" ]]; then
    # A domain change may not appropriate a certificate from another service.
    python3 - "$PREVIOUS_IDENTITY" "$DOMAIN" <<'PY_CERT'
import base64, json, pathlib, sys
previous = json.loads(base64.b64decode(sys.argv[1]))
if previous['domain'] != sys.argv[2]:
    record = pathlib.Path('/var/lib/cdn-xhttp/certificates') / (sys.argv[2] + '.json')
    if not record.is_file() or json.loads(record.read_text()).get('role') != previous['role']:
        raise SystemExit('ERROR: New domain already has a certificate not owned by this installation.')
PY_CERT
fi
for unit in cdn-xhttp.service cdn-xhttp-health.service; do
    [[ "$(systemctl is-enabled "$unit" 2>/dev/null || true)" != masked ]] || fail "$unit is masked."
    [[ ! -d "/etc/systemd/system/$unit.d" ]] || fail "Unmanaged service overrides: $unit"
    fragment=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null || true)
    [[ -z "$fragment" || ( "$MANAGED" == 1 && "$fragment" == "/etc/systemd/system/$unit" ) ]] || fail "Unmanaged service unit: $unit"
    [[ -z "$(systemctl show -p DropInPaths --value "$unit" 2>/dev/null || true)" ]] || fail "Unmanaged service overrides: $unit"
done
XRAY_ACTIVE=0; XRAY_ENABLED=0; HEALTH_ACTIVE=0; HEALTH_ENABLED=0
NGINX_ACTIVE=0; NGINX_ENABLED=0
systemctl is-active --quiet cdn-xhttp.service && XRAY_ACTIVE=1
systemctl is-enabled --quiet cdn-xhttp.service 2>/dev/null && XRAY_ENABLED=1
systemctl is-active --quiet cdn-xhttp-health.service && HEALTH_ACTIVE=1
systemctl is-enabled --quiet cdn-xhttp-health.service 2>/dev/null && HEALTH_ENABLED=1
systemctl is-active --quiet nginx.service && NGINX_ACTIVE=1
systemctl is-enabled --quiet nginx.service 2>/dev/null && NGINX_ENABLED=1

package_file_unchanged() {
    local file="$1" expected actual
    expected=$(dpkg-query -W -f='${Conffiles}\n' nginx-common 2>/dev/null | awk -v path="$file" '$1 == path { print $2 }')
    [[ "$expected" =~ ^[0-9a-f]{32}$ ]] || return 1
    actual=$(md5sum "$file" | awk '{print $1}')
    [[ "$expected" == "$actual" ]]
}
check_nginx() {
    local file
    [[ ! -d /etc/nginx ]] && return 0
    [[ -f /etc/nginx/nginx.conf ]] || fail "Existing nginx directory is incomplete."
    package_file_unchanged /etc/nginx/nginx.conf || fail "nginx.conf is customized; use a dedicated VPS."
    [[ -z "$(systemctl show -p DropInPaths --value nginx.service 2>/dev/null || true)" ]] || fail "nginx has service overrides; use a dedicated VPS."
    file=$(systemctl show -p FragmentPath --value nginx.service 2>/dev/null || true)
    [[ "$file" == /lib/systemd/system/nginx.service || "$file" == /usr/lib/systemd/system/nginx.service ]] || fail "nginx uses a custom service unit."
    shopt -s nullglob dotglob
    for file in /etc/nginx/conf.d/*; do
        fail "Unmanaged nginx configuration: $file"
    done
    for file in /etc/nginx/sites-enabled/*; do
        case "$file" in
            /etc/nginx/sites-enabled/cdn-xhttp.conf)
                [[ "$MANAGED" == 1 && -L "$file" && "$(readlink -f "$file")" == /etc/nginx/sites-available/cdn-xhttp.conf ]] || fail "Unmanaged nginx site: $file"
                ;;
            /etc/nginx/sites-enabled/default)
                [[ -L "$file" && "$(readlink -f "$file")" == /etc/nginx/sites-available/default ]] || fail "Nonstandard nginx default site."
                package_file_unchanged /etc/nginx/sites-available/default || fail "nginx default site was customized."
                ;;
            *) fail "Unmanaged nginx site: $file" ;;
        esac
    done
    shopt -u nullglob dotglob
    nginx -t
}
[[ "$ROLE" != origin ]] || check_nginx

check_listener() {
    local port="$1" allowed="$2" listing pids pid executable expected_pid
    listing=$(ss -H -lntp "sport = :$port")
    [[ -z "$listing" ]] && return 0
    pids=$(printf '%s\n' "$listing" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)
    [[ -n "$pids" ]] || fail "Cannot identify listener on TCP $port."
    for pid in $pids; do
        executable=$(readlink -f "/proc/$pid/exe" || true)
        case "$allowed" in
            nginx)
                [[ "$executable" == /usr/sbin/nginx ]] || fail "Unrelated listener on TCP $port."
                ;;
            xray)
                expected_pid=$(systemctl show -p MainPID --value cdn-xhttp.service)
                [[ "$MANAGED" == 1 && "$pid" == "$expected_pid" && "$executable" == /opt/cdn-xhttp/xray ]] || fail "Unrelated listener on TCP $port."
                ;;
            health)
                expected_pid=$(systemctl show -p MainPID --value cdn-xhttp-health.service)
                [[ "$MANAGED" == 1 && "$pid" == "$expected_pid" ]] || fail "Unrelated listener on TCP $port."
                ;;
            *) fail "TCP $port is already in use." ;;
        esac
    done
}
if [[ "$ROLE" == origin ]]; then
    check_listener 80 nginx
    check_listener 443 nginx
    check_listener 8003 xray
    check_listener 8004 health
else
    check_listener 80 none
    check_listener 10443 xray
fi

STAGING=$(mktemp -d /tmp/cdn-xhttp-root.XXXXXXXX)
BACKUP=''; MUTATING=0; COMPLETE=0
restore_service() {
    local unit="$1" active="$2" enabled="$3"
    if [[ "$enabled" == 1 ]]; then systemctl enable "$unit"; else systemctl disable "$unit" 2>/dev/null || true; fi
    if [[ "$active" == 1 ]]; then systemctl restart "$unit"; else systemctl stop "$unit" 2>/dev/null || true; fi
}
finish() {
    local result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [[ "$COMPLETE" == 0 && "$MUTATING" == 1 ]]; then
        note "Deployment failed. Restoring owned files and service state; backup: $BACKUP"
        systemctl stop cdn-xhttp.service
        [[ "$ROLE" != origin ]] || systemctl stop cdn-xhttp-health.service
        for item in "${BACKUP_PATHS[@]}"; do
            rm -rf -- "$item"
            if [[ -e "$BACKUP/files$item" || -L "$BACKUP/files$item" ]]; then
                mkdir -p -- "$(dirname "$item")"
                cp -a -- "$BACKUP/files$item" "$item"
            fi
        done
        systemctl daemon-reload
        restore_service cdn-xhttp.service "$XRAY_ACTIVE" "$XRAY_ENABLED"
        if [[ "$ROLE" == origin ]]; then
            restore_service cdn-xhttp-health.service "$HEALTH_ACTIVE" "$HEALTH_ENABLED"
            restore_service nginx.service "$NGINX_ACTIVE" "$NGINX_ENABLED"
        fi
        note "Packages, issued certificates and firewall allowances are retained. Inspect any restore errors above."
    fi
    rm -rf -- "$STAGING"
    exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
note "Preflight passed: Ubuntu $VERSION_ID, $ARCH, $ROLE. Installing dependencies."
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l
apt-get -o DPkg::Lock::Timeout=120 update
PACKAGES=(ca-certificates curl unzip certbot dnsutils python3)
[[ "$ROLE" != origin ]] || PACKAGES+=(nginx)
apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "${PACKAGES[@]}"
[[ "$ROLE" != origin ]] || check_nginx

# Fail on stale or conflicting A/AAAA records before writing application files.
{ dig +short A "$DOMAIN"; dig +short AAAA "$DOMAIN"; } > "$STAGING/dns.txt"
python3 - "$SERVER_IP" "$STAGING/dns.txt" <<'PY_DNS'
import ipaddress, pathlib, sys
expected = ipaddress.ip_address(sys.argv[1])
addresses = set()
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    try:
        addresses.add(ipaddress.ip_address(line.strip()))
    except ValueError:
        pass  # A CNAME printed by dig is not an address.
if addresses != {expected}:
    raise SystemExit('ERROR: Domain A/AAAA must resolve only to the supplied server IP. Fix DNS before retrying.')
PY_DNS
note "Downloading the pinned Xray release and checking SHA256."
DOWNLOAD="https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-linux-$ARCH.zip"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 600 "$DOWNLOAD" -o "$STAGING/xray.zip"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 120 "$DOWNLOAD.dgst" -o "$STAGING/xray.zip.dgst"
EXPECTED=$(awk -F '= ' '/256=/ {gsub(/\r/, "", $2); print tolower($2)}' "$STAGING/xray.zip.dgst")
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || fail "Invalid SHA256 digest document."
ACTUAL=$(sha256sum "$STAGING/xray.zip" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || fail "Xray archive checksum mismatch."
unzip -q "$STAGING/xray.zip" xray -d "$STAGING"
chmod 755 "$STAGING/xray"
"$STAGING/xray" version > "$STAGING/xray-version.txt"
sed -n '1p' "$STAGING/xray-version.txt"

[[ ! -L /var/backups/cdn-xhttp ]] || fail "Unexpected backup directory symlink."
install -d -m 700 /var/backups/cdn-xhttp
BACKUP=$(mktemp -d /var/backups/cdn-xhttp/deploy-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX)
install -d -m 700 "$BACKUP/files"
printf 'ROLE=%s\nXRAY_ACTIVE=%s\nXRAY_ENABLED=%s\nHEALTH_ACTIVE=%s\nHEALTH_ENABLED=%s\nNGINX_ACTIVE=%s\nNGINX_ENABLED=%s\n' "$ROLE" "$XRAY_ACTIVE" "$XRAY_ENABLED" "$HEALTH_ACTIVE" "$HEALTH_ENABLED" "$NGINX_ACTIVE" "$NGINX_ENABLED" > "$BACKUP/service-state"
BACKUP_PATHS=("${OWN_PATHS[@]}")
[[ "$ROLE" != origin ]] || BACKUP_PATHS+=(/etc/nginx/sites-enabled/default)
for item in "${BACKUP_PATHS[@]}"; do
    if [[ -e "$item" || -L "$item" ]]; then cp -a --parents -- "$item" "$BACKUP/files"; fi
done
MUTATING=1
note "Root-only backup saved: $BACKUP"
"""


_INSTALL = r"""
install -d -m 755 /opt/cdn-xhttp
install -d -m 750 -o root -g nogroup /etc/cdn-xhttp
install -m 755 "$STAGING/xray" /opt/cdn-xhttp/xray.new
mv -f /opt/cdn-xhttp/xray.new /opt/cdn-xhttp/xray
install -m 640 -o root -g nogroup "$STAGING/config.json" /etc/cdn-xhttp/config.json
install -m 600 -o root -g root "$STAGING/setup.json" /etc/cdn-xhttp/setup.json
install -m 644 "$STAGING/cdn-xhttp.service" /etc/systemd/system/cdn-xhttp.service
install -d -m 700 /var/lib/cdn-xhttp
# A domain record is written only after certbot has issued that certificate
# and is retained with it on rollback; the global owner changes only on
# successful completion. A failed attempt without a certificate leaves no
# claim that could block a retry with corrected domains.
install -d -m 700 /var/lib/cdn-xhttp/certificates
# Migrate the legacy single ownership record before retaining a new domain.
# This lets an existing installation return to its own earlier certificate.
python3 - <<'PY_KEEP_CERT'
import json, pathlib
base = pathlib.Path('/var/lib/cdn-xhttp')
live = pathlib.Path('/etc/letsencrypt/live')
owner = base / 'certificate-owner.json'
if owner.exists():
    identity = json.loads(owner.read_text())
    record = base / 'certificates' / (identity['domain'] + '.json')
    if record.is_symlink():
        raise SystemExit('ERROR: Certificate ownership record is a symlink.')
    # A marker left by a failed first installation of an earlier release has
    # no certificate behind it and must not become a domain record.
    if not record.exists() and (live / identity['domain']).exists():
        record.write_text(json.dumps(identity, sort_keys=True) + '\n')
        record.chmod(0o600)
PY_KEEP_CERT

if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    note "UFW is active: preserving SSH before adding service rules."
    ufw allow "$SSH_PORT/tcp"
    ufw allow 80/tcp
    if [[ "$ROLE" == origin ]]; then
        ufw allow 443/tcp
    else
        ufw allow from "$ORIGIN_IP" to any port 10443 proto tcp
    fi
else
    note "UFW is inactive/absent. Provider firewall must permit SSH, 80 and the role's TLS port."
fi

if [[ "$ROLE" == origin ]]; then
    install -d -m 755 /var/www/cdn-xhttp-acme
    install -m 644 "$STAGING/health.py" /opt/cdn-xhttp/health.py
    install -m 644 "$STAGING/cdn-xhttp-health.service" /etc/systemd/system/cdn-xhttp-health.service
    install -m 644 "$STAGING/nginx-http.conf" /etc/nginx/sites-available/cdn-xhttp.conf
    rm -f /etc/nginx/sites-enabled/default
    ln -sfn /etc/nginx/sites-available/cdn-xhttp.conf /etc/nginx/sites-enabled/cdn-xhttp.conf
    nginx -t
    systemctl daemon-reload
    systemctl enable --now nginx.service
    systemctl reload nginx.service
    certbot certonly --webroot -w /var/www/cdn-xhttp-acme --non-interactive --agree-tos --email "$EMAIL" --cert-name "$DOMAIN" --keep-until-expiring -d "$DOMAIN"
    printf '%s' "$IDENTITY" | base64 -d > "/var/lib/cdn-xhttp/certificates/$DOMAIN.json"
    install -m 644 "$STAGING/nginx-tls.conf" /etc/nginx/sites-available/cdn-xhttp.conf
else
    certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" --cert-name "$DOMAIN" --keep-until-expiring -d "$DOMAIN"
    printf '%s' "$IDENTITY" | base64 -d > "/var/lib/cdn-xhttp/certificates/$DOMAIN.json"
    install -d -m 750 -o root -g nogroup /etc/cdn-xhttp/tls
    install -m 640 -o root -g nogroup "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /etc/cdn-xhttp/tls/fullchain.pem
    install -m 640 -o root -g nogroup "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /etc/cdn-xhttp/tls/privkey.pem
fi

# Check the config as the actual service account, including certificate access.
runuser -u nobody -- /opt/cdn-xhttp/xray run -test -config /etc/cdn-xhttp/config.json
systemctl daemon-reload
systemctl enable cdn-xhttp.service
systemctl restart cdn-xhttp.service
if [[ "$ROLE" == origin ]]; then
    systemctl enable cdn-xhttp-health.service
    systemctl restart cdn-xhttp-health.service
    nginx -t
    systemctl reload nginx.service
fi
sleep 2
systemctl is-active --quiet cdn-xhttp.service || fail "Xray failed to stay active."
if [[ "$ROLE" == origin ]]; then
    systemctl is-active --quiet cdn-xhttp-health.service || fail "Health probe failed to stay active."
    systemctl is-active --quiet nginx.service || fail "nginx is inactive."
    ss -H -lnt 'sport = :8003' | grep -q '127.0.0.1:8003' || fail "Xray is not listening on loopback:8003."
    ss -H -lnt 'sport = :8004' | grep -q '127.0.0.1:8004' || fail "Health probe is not listening on loopback:8004."
    RESULT=$(curl --silent --show-error --fail --max-time 15 --noproxy '*' --resolve "$DOMAIN:443:127.0.0.1" -X OPTIONS -H 'X-Data-0: probe' --data-binary 'test' -o "$STAGING/probe.json" -w '%{http_code}' "https://$DOMAIN/cdn-check")
    [[ "$RESULT" == 200 ]] || fail "Local origin OPTIONS probe did not return 200."
    python3 - "$STAGING/probe.json" <<'PY_PROBE'
import hashlib, json, pathlib, sys
body = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = {
    'method': 'OPTIONS', 'length': 4, 'sha256': hashlib.sha256(b'test').hexdigest(),
    'header_bytes': 5, 'header_sha256': hashlib.sha256(b'probe').hexdigest(),
}
if body != expected:
    raise SystemExit('ERROR: Local origin OPTIONS body/header integrity check failed.')
PY_PROBE
else
    ss -H -lnt 'sport = :10443' | grep -q ':10443' || fail "Exit is not listening on 10443."
fi

install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
{
    printf '#!/bin/sh\nset -eu\n'
    printf 'EXPECTED_LINEAGE=%q\n' "/etc/letsencrypt/live/$DOMAIN"
    cat <<'HOOK'
[ "${RENEWED_LINEAGE:-}" = "$EXPECTED_LINEAGE" ] || exit 0
HOOK
    if [[ "$ROLE" == origin ]]; then
        printf 'nginx -t && systemctl reload nginx.service\n'
    else
        cat <<'HOOK'
install -m 640 -o root -g nogroup "$RENEWED_LINEAGE/fullchain.pem" /etc/cdn-xhttp/tls/fullchain.pem
install -m 640 -o root -g nogroup "$RENEWED_LINEAGE/privkey.pem" /etc/cdn-xhttp/tls/privkey.pem
runuser -u nobody -- /opt/cdn-xhttp/xray run -test -config /etc/cdn-xhttp/config.json
systemctl restart cdn-xhttp.service
HOOK
    fi
} > /etc/letsencrypt/renewal-hooks/deploy/cdn-xhttp.sh
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/cdn-xhttp.sh
systemctl enable --now certbot.timer
printf '%s' "$IDENTITY" | base64 -d > /etc/cdn-xhttp/deployment.json
chmod 600 /etc/cdn-xhttp/deployment.json
printf '%s' "$IDENTITY" | base64 -d > /var/lib/cdn-xhttp/certificate-owner.json
COMPLETE=1
note "$ROLE installation complete. Backup retained: $BACKUP"
"""


def _redact(text: str, secrets: list[str]) -> str:
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def _connect(
    server: dict,
    password: str | None,
    known_hosts: Path,
    confirm_host: Callable[[str], bool],
):
    import paramiko

    known_hosts = Path(known_hosts)

    class ConfirmHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            digest = (
                base64.b64encode(hashlib.sha256(key.asbytes()).digest())
                .decode()
                .rstrip("=")
            )
            if not confirm_host(f"{hostname}: {key.get_name()} SHA256:{digest}"):
                raise RemoteError("SSH host key was not accepted")
            client.get_host_keys().add(hostname, key.get_name(), key)
            known_hosts.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(
                prefix=".known-hosts-", dir=str(known_hosts.parent)
            )
            os.close(fd)
            try:
                client.save_host_keys(temporary)
                os.chmod(temporary, 0o600)
                os.replace(temporary, known_hosts)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(ConfirmHostKey())
        client.connect(
            server["host"],
            port=int(server.get("port", 22)),
            username=server.get("user", "root"),
            password=password,
            allow_agent=password is None,
            look_for_keys=password is None,
            timeout=20,
            auth_timeout=30,
            banner_timeout=30,
        )
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(20)
        return client
    except BaseException:
        client.close()
        raise


_RECOVER_SOURCE = r"""
import base64, fcntl, json, pathlib
try:
    lock = open('/run/lock/cdn-xhttp.lock', 'a')
except OSError as exc:
    raise SystemExit('ERROR: Cannot open the deployment lock: %s' % exc.strerror)
with lock:
    try:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('ERROR: Another cdn-xhttp deployment is running; retry when it finishes')
    root = pathlib.Path('/etc/cdn-xhttp')
    if root.is_symlink():
        raise SystemExit('ERROR: Managed directory is a symlink')
    payload = {}
    for name in ('deployment.json', 'config.json', 'setup.json'):
        p = root / name
        if p.is_symlink():
            raise SystemExit('ERROR: Managed file is a symlink: %s' % name)
        if p.exists():
            if p.stat().st_size > 1048576:
                raise SystemExit('ERROR: Managed file is too large: %s' % name)
            try:
                payload[name] = json.loads(p.read_text())
            except ValueError:
                raise SystemExit('ERROR: Managed file is not valid JSON: %s' % name)
    if payload and ('deployment.json' not in payload or 'config.json' not in payload):
        raise SystemExit('ERROR: Incomplete installation; inspect the VPS before continuing')
    print('CDN_SETUP:' + base64.b64encode(json.dumps(payload).encode()).decode())
"""


def _recovery_failure(status: int, lines: list[str]) -> str:
    """Explain a failed read with the last remote lines; they are redacted."""
    details = [
        line.strip()[:300]
        for line in lines
        if line.strip() and not line.startswith("CDN_SETUP:")
    ][-5:]
    message = f"Could not read the saved setup on the server (exit status {status})"
    if not details:
        return message + "; the server printed no details"
    return message + ": " + " | ".join(details)


def _recovered_config(payload: dict, server: dict) -> dict | None:
    """Decode owned v0.2 metadata, or reconstruct the supported v0.1 layout."""
    from .config import XRAY_VERSION, validate

    if not payload:
        return None
    identity = payload["deployment.json"]
    if identity.get("role") != "origin":
        raise RemoteError("Enter the origin server, not the exit server")
    runtime = payload["config.json"]
    legacy = "setup.json" not in payload
    if not legacy:
        c = validate(payload["setup.json"])
        if c["origin"]["host"] != server["host"]:
            raise RemoteError("Saved origin IP differs from the connected server")
        c["origin"] = dict(server)
    else:
        try:
            inbound = runtime["inbounds"][0]
            xhttp = inbound["streamSettings"]["xhttpSettings"]
            # Releases from 0.4.0 keep padding inside xhttpSettings.extra.
            xhttp = {**xhttp, **xhttp.get("extra", {})}
            uuids = [user["id"] for user in inbound["settings"]["users"]]
            c = {
                "origin": dict(server),
                "origin_domain": identity["domain"],
                "cdn_domain": identity["cdn_domain"],
                "exit": None,
                "email": "recovery@example.com",
                "name": "CDN XHTTP",
                "uuids": uuids,
                "uuid": uuids[0],
                "path": xhttp["path"],
                "padding_key": xhttp["xPaddingKey"],
                "profile": "fast",
                "xray_version": XRAY_VERSION,
            }
            outbound = runtime["outbounds"][0]
            if outbound["protocol"] == "vless":
                c["exit"] = {
                    "host": outbound["settings"]["vnext"][0]["address"],
                    "port": 22,
                    "user": "root",
                }
                c["exit_domain"] = outbound["streamSettings"]["tlsSettings"][
                    "serverName"
                ]
            c = validate(c)
        except (KeyError, IndexError, TypeError, ValueError):
            raise RemoteError(
                "Unsupported legacy configuration; existing settings were preserved"
            ) from None
    current, *earlier = _accepted_runtimes(c, "origin")
    if identity != json.loads(_identity(c, "origin")) or (
        runtime != current and runtime not in earlier
    ):
        raise RemoteError(
            "Server configuration differs from its saved setup; inspect it before changing settings"
        )
    if runtime != current:
        # Installed by an earlier release: links of this release need a
        # reinstall of the server with the same settings and UUIDs.
        c["_server_outdated"] = True
    if legacy:
        c["email"] = ""
        c["_recovered_legacy"] = True
    return c


def recover_config(
    server: dict,
    *,
    password: str | None,
    sudo_password: str | None,
    known_hosts: Path,
    confirm_host: Callable[[str], bool],
) -> dict | None:
    """Read an existing installation over verified SSH without changing it."""
    import paramiko

    client = None
    try:
        client = _connect(server, password, known_hosts, confirm_host)
        command = "python3 -c " + shlex.quote(_RECOVER_SOURCE)
        sudo_input = None
        if server.get("user", "root") != "root":
            command = "sudo -k -S -p '' -- " + command
            sudo_input = sudo_password
        lines = []

        def collect(line):
            if sum(map(len, lines)) + len(line) > 2 * 1024 * 1024:
                raise RemoteError("Server setup response is too large")
            lines.append(line)

        try:
            _stream_command(
                client,
                command,
                stdin_secret=sudo_input,
                log=collect,
                # sudo or Python may echo input; never surface a password.
                secrets=[password or "", sudo_password or ""],
                timeout=60,
            )
        except RemoteCommandError as exc:
            # The output was collected, not printed: report it here.
            raise RemoteError(_recovery_failure(exc.status, lines)) from None
        encoded = [
            line.removeprefix("CDN_SETUP:")
            for line in lines
            if line.startswith("CDN_SETUP:")
        ]
        if len(encoded) != 1:
            raise RemoteError("Server did not return a valid saved setup")
        try:
            payload = json.loads(base64.b64decode(encoded[0], validate=True))
            return _recovered_config(payload, server)
        except RemoteError:
            raise
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            # Validation messages are fixed texts without secrets.
            reason = (
                str(exc)
                if type(exc) is ValueError and str(exc)
                else type(exc).__name__
            )
            raise RemoteError(
                f"Saved server setup is not supported ({reason}); existing settings were preserved"
            ) from None
    except paramiko.BadHostKeyException:
        raise RemoteError(
            "SSH host key changed. Verify it independently before updating known_hosts."
        ) from None
    except paramiko.AuthenticationException:
        raise RemoteError("SSH authentication failed") from None
    except RemoteError:
        raise
    except (paramiko.SSHException, OSError, EOFError, ValueError, KeyError, TypeError):
        raise RemoteError(
            "Unable to recover a supported server setup; existing settings were preserved"
        ) from None
    finally:
        if client is not None:
            client.close()


def _stream_command(
    client,
    command: str,
    *,
    stdin_secret: str | None = None,
    log: Callable[[str], None],
    secrets: list[str],
    timeout: float = 3600,
) -> None:
    """Drain output before exit_status to avoid SSH channel window deadlock."""
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise RemoteError("SSH connection is not active")
    channel = transport.open_session(timeout=30)
    channel.set_combine_stderr(True)
    pending = b""
    deadline = time.monotonic() + timeout
    timed_out = "SSH deployment timed out; inspect the server before retrying"

    def consume(chunk: bytes) -> None:
        nonlocal pending
        pending += chunk
        # Preserve complete lines so chunk boundaries cannot expose a
        # credential split between two recv calls.
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            log(_redact(line.decode("utf-8", errors="replace").rstrip("\r"), secrets))
        if len(pending) > 1024 * 1024:
            raise RemoteError("Remote installer emitted an excessively long output line")

    try:
        channel.exec_command(command)
        if stdin_secret is not None:
            channel.sendall((stdin_secret + "\n").encode("utf-8"))
        channel.shutdown_write()
        while True:
            if time.monotonic() >= deadline:
                raise RemoteError(timed_out)
            if channel.recv_ready():
                consume(channel.recv(65536))
            elif channel.exit_status_ready():
                # Output can arrive between the recv_ready() and
                # exit_status_ready() checks; read until EOF so the last
                # lines, usually the error, are never lost.
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RemoteError(timed_out)
                    channel.settimeout(remaining)
                    try:
                        chunk = channel.recv(65536)
                    except socket.timeout:
                        raise RemoteError(timed_out) from None
                    if not chunk:
                        break
                    consume(chunk)
                break
            elif not transport.is_active():
                raise RemoteError(
                    "SSH connection lost; inspect the server before retrying"
                )
            else:
                time.sleep(0.05)
        if pending:
            log(_redact(pending.decode("utf-8", errors="replace"), secrets))
        status = channel.recv_exit_status()
        if status != 0:
            raise RemoteCommandError(status)
    finally:
        channel.close()


def deploy_server(
    config: dict,
    role: str,
    *,
    password: str | None,
    sudo_password: str | None,
    known_hosts: Path,
    confirm_host: Callable[[str], bool],
    log: Callable[[str], None],
    previous: dict | None = None,
) -> None:
    """Deploy one role; verify or explicitly trust its SSH host fingerprint.

    Credentials are sent through SSH authentication / sudo stdin only. The
    remote temporary script has mode 0600 in a 0700 random directory and is
    removed after the connection succeeds or the installer fails.
    """
    try:
        import paramiko
    except ImportError as exc:
        raise RemoteError(
            "Install dependencies first: python -m pip install -e ."
        ) from exc
    script = (
        render_bootstrap(config, role, previous=previous)
        if previous
        else render_bootstrap(config, role)
    )
    server = config[role]
    known_hosts = Path(known_hosts)
    secrets = [
        config["uuid"],
        *config.get("uuids", [config["uuid"]]),
        password or "",
        sudo_password or "",
    ]

    client = None
    remote_dir = None
    try:
        client = _connect(server, password, known_hosts, confirm_host)
        stdin, stdout, stderr = client.exec_command(
            "umask 077; mktemp -d /tmp/cdn-xhttp-ssh.XXXXXXXX", timeout=30
        )
        stdin.close()
        remote_dir = stdout.read().decode("utf-8").strip()
        if stdout.channel.recv_exit_status() != 0 or not re.fullmatch(
            r"/tmp/cdn-xhttp-ssh\.[A-Za-z0-9]{8}", remote_dir
        ):
            remote_dir = None
            raise RemoteError("Unable to create the remote staging directory")
        remote_script = remote_dir + "/bootstrap.sh"
        with client.open_sftp() as sftp:
            with sftp.open(remote_script, "wb") as output:
                output.write(script.encode("utf-8"))
            sftp.chmod(remote_script, 0o600)
        command = "bash -- " + shlex.quote(remote_script) + ' "${SSH_CONNECTION##* }"'
        sudo_input = None
        if server.get("user", "root") != "root":
            sudo_input = sudo_password
            # -k prevents an unrelated cached credential from changing behavior.
            command = "sudo -k -S -p '' -- " + command
        log(f"Deploying {role} on {server['host']} over verified SSH")
        _stream_command(
            client, command, stdin_secret=sudo_input, log=log, secrets=secrets
        )
    except RemoteError:
        raise
    except paramiko.BadHostKeyException as exc:
        raise RemoteError(
            "SSH host key changed. Verify it independently before updating known_hosts."
        ) from exc
    except paramiko.AuthenticationException as exc:
        raise RemoteError("SSH authentication failed") from exc
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise RemoteError(_redact(f"SSH deployment failed: {exc}", secrets)) from exc
    finally:
        if remote_dir is not None:
            try:
                with client.open_sftp() as sftp:
                    try:
                        sftp.remove(remote_dir + "/bootstrap.sh")
                    finally:
                        sftp.rmdir(remote_dir)
            except (OSError, EOFError, paramiko.SSHException):
                log(
                    "Remote temporary script cleanup could not be confirmed; remove the private /tmp/cdn-xhttp-ssh.* directory on the VPS."
                )
        if client is not None:
            client.close()
