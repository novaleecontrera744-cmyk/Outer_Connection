#!/usr/bin/env python3
"""Fail-closed outer VLESS gateway for a Proton WireGuard connection."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import platform
import pwd
import re
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import syslog
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


class OuterError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Paths:
    root: Path = Path("/")

    def at(self, name: str) -> Path:
        return self.root / name.lstrip("/")

    @property
    def prefix(self) -> Path:
        return self.at("/usr/local/lib/outer-vpn")

    @property
    def script(self) -> Path:
        return self.prefix / "outer.py"

    @property
    def sing(self) -> Path:
        return self.prefix / "sing-box"

    @property
    def xray(self) -> Path:
        return self.prefix / "xray"

    @property
    def manifest(self) -> Path:
        return self.prefix / "install.json"

    @property
    def unit(self) -> Path:
        return self.at("/etc/systemd/system/outer-vpn.service")

    @property
    def env(self) -> Path:
        return self.at("/etc/outer-vpn/outer.env")

    @property
    def runtime(self) -> Path:
        return self.at("/run/outer-vpn")

    @property
    def state(self) -> Path:
        return self.runtime / "state.json"

    @property
    def backups(self) -> Path:
        return self.at("/var/lib/outer-vpn/backups")

    @property
    def lock(self) -> Path:
        return self.at("/run/lock/outer-vpn.lock")


PATHS = Paths()
NAMESPACE = "outer-vpn"
HOST_IF = "ogw-host"
NS_IF = "ogw-ns"
TUN_IF = "ogw-tun"
HOST_IP = "10.203.0.1"
NS_IP = "10.203.0.2"
VETH_NET = "10.203.0.0/30"
ROUTE_TABLE = "50073"
IPV6_TABLE = "50074"
PROTON_TABLE = "50075"
RULE_ENDPOINT = "109"
RULE_SOURCE = "110"
RULE_SOURCE_DROP = "111"
RULE_IPV6 = "112"
GATEWAY_METRIC = "42700"
BLACKHOLE_METRIC = "42760"
MANAGED_ROUTE_PROTO = "static"
SOCKS_PORT = 10808
DEFAULT_DNS = "1.1.1.1"
DEFAULT_PROTON_INTERFACE = "proton0"
UNIT_NAME = "outer-vpn.service"
LEGACY_UNIT = "outer-gateway.service"
MANAGED_MARKER = "# Managed by outer.py; changes may be replaced."


SYSTEM_TOOLS = {
    "ip": ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"),
    "nft": ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"),
    "sysctl": ("/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl", "/bin/sysctl"),
    "wg": ("/usr/bin/wg", "/usr/sbin/wg", "/bin/wg", "/sbin/wg"),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    "resolvectl": ("/usr/bin/resolvectl", "/bin/resolvectl"),
    "unshare": ("/usr/bin/unshare", "/bin/unshare", "/usr/sbin/unshare", "/sbin/unshare"),
}


def executable_path(name):
    name = str(name)
    if os.path.isabs(name):
        return name
    if name not in SYSTEM_TOOLS:
        raise OuterError("An unrecognized external command was rejected.")
    for candidate in SYSTEM_TOOLS[name]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise OuterError(f"Required system tool {name} was not found in trusted system directories.")


def command_argv(args):
    command = [str(arg) for arg in args]
    if not command:
        raise OuterError("An empty external command was rejected.")
    command[0] = executable_path(command[0])
    if Path(command[0]).name == "ip" and command[1:3] == ["netns", "exec"]:
        if len(command) < 5:
            raise OuterError("An incomplete namespace command was rejected.")
        command[4] = executable_path(command[4])
    if Path(command[0]).name == "unshare" and command[1:3] == ["--net", "--"]:
        if len(command) < 4:
            raise OuterError("An incomplete namespace command was rejected.")
        command[3] = executable_path(command[3])
    return command


def attempted_argv(args):
    attempted = [str(arg) for arg in args]
    if attempted and attempted[0] in SYSTEM_TOOLS:
        attempted[0] = SYSTEM_TOOLS[attempted[0]][0]
    if len(attempted) >= 5 and attempted[1:3] == ["netns", "exec"] and attempted[4] in SYSTEM_TOOLS:
        attempted[4] = SYSTEM_TOOLS[attempted[4]][0]
    return attempted


def redact_text(value, secrets=()):
    text = str(value or "")
    for secret in sorted((str(item) for item in secrets if item and len(str(item)) >= 4),
                         key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    text = re.sub(r"(?i)vless://[^\s\"']+", "[redacted VLESS URL]", text)
    text = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                  "[redacted UUID]", text)
    text = re.sub(
        r"(?i)(\b(?:password|passwd|secret|token|private[_-]?key|public[_-]?key|short[_-]?id|spider[_-]?x|uuid|pbk|sid|spx)\b"
        r"[\"']?\s*[:=]\s*[\"']?)([^\s\"',}\]]+)",
        r"\1[redacted]", text,
    )
    text = "".join(ch if ch in "\n\t" or ord(ch) >= 32 and ord(ch) != 127 else "?" for ch in text)
    if len(text) > 8192:
        text = text[:8192] + "\n[stderr truncated]"
    return text


def command_failure(args, returncode, stderr, *, secrets=(), label="Command failed"):
    safe_args = []
    hide_next = False
    for arg in map(str, args):
        if hide_next:
            safe_args.append("[redacted]")
            hide_next = False
        else:
            safe_args.append(redact_text(arg, secrets))
            hide_next = bool(re.fullmatch(r"(?i)--?(?:password|passwd|secret|token|uuid|pbk|private-key|public-key)", arg))
    command = shlex.join(safe_args)
    detail = redact_text(stderr, secrets).strip() or "(empty)"
    code = f" (exit {returncode})" if returncode is not None else ""
    return OuterError(f"{label}{code}.\nargv: {command}\nstderr: {detail}")


class Runner:
    def __init__(self):
        self.secrets = set()

    def add_secrets(self, *values):
        self.secrets.update(str(value) for value in values if value)

    def run(self, args, *, input_text=None, check=True, timeout=30):
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        try:
            command = command_argv(args)
        except OuterError as exc:
            raise command_failure(attempted_argv(args), None, str(exc), secrets=self.secrets,
                                  label="Could not resolve command") from exc
        try:
            result = subprocess.run(
                command, input=input_text, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise command_failure(command, None, exc.stderr, secrets=self.secrets,
                                  label="Command timed out") from exc
        except OSError as exc:
            raise command_failure(command, None, exc.strerror or type(exc).__name__,
                                  secrets=self.secrets, label="Could not run command") from exc
        if check and result.returncode:
            raise command_failure(command, result.returncode, result.stderr, secrets=self.secrets)
        return result

    def json(self, args):
        result = self.run(args)
        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise command_failure(getattr(result, "args", args), result.returncode, result.stderr,
                                  secrets=self.secrets, label="Command returned invalid JSON") from exc


RUNNER = Runner()


def register_settings_secrets(settings, runner=RUNNER):
    if hasattr(runner, "add_secrets"):
        vless = settings.get("vless", {})
        runner.add_secrets(vless.get("uuid"), vless.get("public_key"),
                           vless.get("short_id"), vless.get("spider_x"))


def require_root():
    if os.geteuid() != 0:
        raise OuterError("This command requires root; run it with sudo.")


def _ensure_dir(path: Path, mode=0o755):
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise OuterError("A required directory is not a real directory.")


def atomic_write(path: Path, data: bytes, mode=0o600):
    _ensure_dir(path.parent)
    fd, name = tempfile.mkstemp(prefix=".outer-vpn-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)
        raise


def atomic_json(path: Path, value, mode=0o600):
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(), mode)


def lexists(path: Path):
    return os.path.lexists(path)


def remove_path(path: Path):
    if not lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def _copy_owned(source: Path, target: Path):
    info = source.lstat()
    if stat.S_ISLNK(info.st_mode):
        os.symlink(os.readlink(source), target)
    elif stat.S_ISREG(info.st_mode):
        shutil.copyfile(source, target, follow_symlinks=False)
    elif stat.S_ISDIR(info.st_mode):
        target.mkdir(mode=stat.S_IMODE(info.st_mode))
        for child in source.iterdir():
            _copy_owned(child, target / child.name)
    else:
        raise OuterError("A migration path contains a special file; it was not modified.")
    if os.geteuid() == 0:
        os.chown(target, info.st_uid, info.st_gid, follow_symlinks=False)
    shutil.copystat(source, target, follow_symlinks=False)


def _restore_copy(source: Path, target: Path):
    _ensure_dir(target.parent)
    temporary = target.parent / (".outer-vpn-restore-" + uuid.uuid4().hex)
    try:
        _copy_owned(source, temporary)
        if lexists(target) and ((target.is_dir() and not target.is_symlink())
                                 or (source.is_dir() and not source.is_symlink())):
            remove_path(target)
        os.replace(temporary, target)
    finally:
        if lexists(temporary):
            remove_path(temporary)


def _matches_copy(source: Path, backup: Path):
    if not lexists(source):
        return False
    left, right = source.lstat(), backup.lstat()
    if (stat.S_IFMT(left.st_mode), stat.S_IMODE(left.st_mode), left.st_uid, left.st_gid) != (
        stat.S_IFMT(right.st_mode), stat.S_IMODE(right.st_mode), right.st_uid, right.st_gid
    ):
        return False
    if stat.S_ISLNK(left.st_mode):
        return os.readlink(source) == os.readlink(backup)
    if stat.S_ISREG(left.st_mode):
        if left.st_size != right.st_size:
            return False
        with source.open("rb") as original, backup.open("rb") as saved:
            while True:
                first, second = original.read(1024 * 1024), saved.read(1024 * 1024)
                if first != second:
                    return False
                if not first:
                    return True
    if stat.S_ISDIR(left.st_mode):
        originals = {child.name for child in source.iterdir()}
        saved = {child.name for child in backup.iterdir()}
        return originals == saved and all(_matches_copy(source / name, backup / name) for name in originals)
    return False


class FileTransaction:
    """Keep durable root-only backups and restore touched paths on error."""

    def __init__(self, paths=PATHS, label="change"):
        self.paths = paths
        _ensure_dir(paths.backups, 0o700)
        os.chmod(paths.backups, 0o700)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.directory = paths.backups / f"{stamp}-{label}-{uuid.uuid4().hex[:10]}"
        self.directory.mkdir(mode=0o700)
        self.entries = []
        self._save()

    @classmethod
    def reopen(cls, paths, directory):
        directory = Path(directory)
        if directory.is_symlink() or directory.resolve().parent != paths.backups.resolve():
            raise OuterError("The legacy migration backup path is invalid.")
        try:
            entries = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))["entries"]
            if not isinstance(entries, list) or any(
                not isinstance(item, dict) or not isinstance(item.get("changed"), bool)
                for item in entries
            ):
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise OuterError("The legacy migration backup is incomplete.") from exc
        tx = cls.__new__(cls)
        tx.paths, tx.directory, tx.entries = paths, directory, entries
        return tx

    def _save(self):
        atomic_json(self.directory / "manifest.json", {"entries": self.entries})

    def snapshot(self, path: Path):
        path = Path(path)
        if any(item["path"] == str(path) for item in self.entries):
            return
        entry = {"path": str(path), "existed": lexists(path), "backup": None, "changed": False}
        if entry["existed"]:
            name = f"{len(self.entries):04d}"
            _copy_owned(path, self.directory / name)
            entry["backup"] = name
        self.entries.append(entry)
        self._save()

    def _prepare_change(self, path: Path):
        self.snapshot(path)
        entry = next(item for item in self.entries if item["path"] == str(path))
        if not entry["changed"]:
            same = (_matches_copy(path, self.directory / entry["backup"])
                    if entry["existed"] else not lexists(path))
            if not same:
                raise OuterError("A file changed after backup; it was not modified.")
            entry["changed"] = True
            self._save()
        return entry

    def write(self, path: Path, data: bytes, mode=0o600):
        self._prepare_change(path)
        atomic_write(path, data, mode)

    def remove(self, path: Path):
        self.snapshot(path)
        entry = next(item for item in self.entries if item["path"] == str(path))
        if not entry["existed"] and not lexists(path):
            return
        self._prepare_change(path)
        remove_path(path)

    def rollback(self):
        failures = []
        for entry in reversed(self.entries):
            if not entry["changed"]:
                continue
            target = Path(entry["path"])
            try:
                if entry["existed"]:
                    _restore_copy(self.directory / entry["backup"], target)
                else:
                    remove_path(target)
                entry["changed"] = False
                self._save()
            except (OSError, OuterError):
                failures.append(str(target))
        if failures:
            raise OuterError(f"File rollback was incomplete; backups are in {self.directory}.")


@contextlib.contextmanager
def operation_lock(paths=PATHS):
    _ensure_dir(paths.lock.parent)
    fd = os.open(paths.lock, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise OuterError("The gateway lock file is not a root-owned regular file.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def service_unit():
    return f"""{MANAGED_MARKER}
[Unit]
Description=Fail-closed outer VLESS gateway for Proton VPN
Wants=network-online.target
After=network-online.target systemd-resolved.service

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/bin/python3 /usr/local/lib/outer-vpn/outer.py _supervise
ExecStopPost=/usr/bin/python3 /usr/local/lib/outer-vpn/outer.py _post-stop
TimeoutStartSec=120
TimeoutStopSec=45
KillMode=mixed
Restart=no

[Install]
WantedBy=multi-user.target
"""


def systemd_active(runner=RUNNER, unit=UNIT_NAME):
    command = ["systemctl", "is-active", "--quiet", unit]
    result = runner.run(command, check=False)
    if result.returncode not in (0, 3, 4):
        raise command_failure(getattr(result, "args", command), result.returncode, result.stderr,
                              secrets=getattr(runner, "secrets", ()), label="Could not inspect service state")
    return result.returncode == 0


def systemd_enabled(runner=RUNNER, unit=UNIT_NAME):
    return runner.run(["systemctl", "is-enabled", unit], check=False).stdout.strip()


def legacy_paths(paths=PATHS):
    found = [
        paths.at("/etc/systemd/system/outer-gateway.service"),
        paths.at("/etc/systemd/system/outer-gateway.service.d/50-xray-bridge.conf"),
        paths.at("/etc/sing-box-gateway"),
        paths.at("/etc/outer-gateway"),
        paths.at("/usr/local/bin/outer-vpn-toggle"),
        paths.at("/usr/local/sbin/outer-vpn-toggle-root"),
        paths.at("/usr/share/applications/Outer-Connection.desktop"),
        paths.at("/usr/local/share/applications/Outer-Connection.desktop"),
    ]
    libexec = paths.at("/usr/local/libexec")
    if libexec.is_dir():
        found.extend(sorted(libexec.glob("outergw-*")))
    sudo_user = os.environ.get("SUDO_USER")
    try:
        account = pwd.getpwnam(sudo_user) if sudo_user else pwd.getpwuid(os.getuid())
        home = Path(account.pw_dir)
        if paths.root != Path("/"):
            home = paths.at(str(home))
        for name in (".local/share/applications/Outer-Connection.desktop",
                     ".config/autostart/Outer-Connection.desktop", "Desktop/Outer-Connection.desktop"):
            candidate = home / name
            if candidate.parent.resolve().is_relative_to(home.resolve()):
                found.append(candidate)
    except (KeyError, OSError, RuntimeError):
        pass
    return [path for path in found if lexists(path)]


def restore_legacy_service(was_active, was_enabled, runner=RUNNER):
    runner.run(["systemctl", "daemon-reload"])
    if was_enabled in ("enabled", "enabled-runtime"):
        command = ["systemctl", "enable"]
        if was_enabled == "enabled-runtime":
            command.append("--runtime")
        runner.run(command + [LEGACY_UNIT])
    if was_active:
        runner.run(["systemctl", "start", LEGACY_UNIT])


def resolve_ipv4(host, port):
    try:
        results = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise OuterError("The outer server could not be resolved to IPv4.") from exc
    for result in results:
        address = result[4][0]
        if ipaddress.IPv4Address(address).is_global:
            return address
    raise OuterError("The outer server has no publicly routable IPv4 address.")


def validate_interface(value):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value) or value in (".", "..", HOST_IF, NS_IF, TUN_IF, "lo"):
        raise ValueError("PROTON_INTERFACE must be a distinct Linux interface name.")
    return value


def validate_dns(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError("DNS_SERVER must be a literal IPv4 address.") from exc
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise ValueError("DNS_SERVER must be a unicast IPv4 address.")
    return str(address)


_ENV_KEYS = frozenset(
    ("VLESS_URL", "PROTON_ENDPOINTS", "PROTON_INTERFACE", "DNS_SERVER", "STRICT_MODE")
)
_REQUIRED_ENV_KEYS = frozenset(("VLESS_URL", "PROTON_ENDPOINTS"))
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_IPV4_RE = re.compile(r"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$")
_UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_FINGERPRINTS = frozenset(
    ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
     "random", "randomized")
)
_VLESS_QUERY_KEYS = frozenset(
    ("type", "security", "flow", "encryption", "sni", "fp", "pbk", "sid", "spx", "headerType")
)
_VLESS_RESULT_KEYS = frozenset(
    ("server", "port", "uuid", "public_key", "server_name", "short_id",
     "fingerprint", "spider_x")
)


def _fail(message):
    raise ValueError(message) from None


def _parse_env_value(raw_value, line_number):
    value = raw_value.strip()
    if not value:
        _fail("Empty environment value at line {}.".format(line_number))

    if value[0] in ("'", '"'):
        quote = value[0]
        if len(value) < 2 or value[-1] != quote or quote in value[1:-1]:
            _fail("Malformed environment value at line {}.".format(line_number))
        value = value[1:-1]

    if not value or "\x00" in value:
        _fail("Malformed environment value at line {}.".format(line_number))
    return value


def parse_env_file(path):
    """Read a strict KEY=value file without shell expansion or evaluation."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except (OSError, TypeError, ValueError, UnicodeError):
        _fail("Unable to read environment file.")

    return parse_env_text(text)


def parse_env_text(text):
    values = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            _fail("Malformed environment file at line {}.".format(line_number))

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not _ENV_KEY_RE.fullmatch(key):
            _fail("Malformed environment key at line {}.".format(line_number))
        if key not in _ENV_KEYS:
            _fail("Unknown environment key at line {}.".format(line_number))
        if key in values:
            _fail("Duplicate environment key at line {}.".format(line_number))
        values[key] = _parse_env_value(raw_value, line_number)

    if not _REQUIRED_ENV_KEYS.issubset(values):
        _fail("A required environment key is missing.")
    return values


def _canonical_ipv4(value):
    if not isinstance(value, str) or not _IPV4_RE.fullmatch(value):
        _fail("Invalid IPv4 address.")
    try:
        return str(ipaddress.IPv4Address(value))
    except (ipaddress.AddressValueError, ValueError):
        _fail("Invalid IPv4 address.")


def parse_proton_endpoints(value):
    """Parse distinct, literal IPv4 addresses from comma/whitespace separators."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        _fail("Invalid Proton endpoint list.")

    endpoints_text = value.strip()
    if (
        endpoints_text.startswith(",")
        or endpoints_text.endswith(",")
        or re.search(r",\s*,", endpoints_text)
    ):
        _fail("Invalid Proton endpoint list.")

    result = []
    seen = set()
    for token in re.split(r"[\s,]+", endpoints_text):
        address = _canonical_ipv4(token)
        if address not in seen:
            seen.add(address)
            result.append(address)
    if not result:
        _fail("Invalid Proton endpoint list.")
    return result


def _canonical_host(value, *, require_dns=False):
    if not isinstance(value, str) or not value or "%" in value:
        _fail("Invalid server host.")
    if any(character.isspace() or ord(character) < 0x21 for character in value):
        _fail("Invalid server host.")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if require_dns:
            _fail("Invalid REALITY server name.")
        return str(address)

    if ":" in value or re.fullmatch(r"[0-9.]+", value):
        _fail("Invalid server host.")
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        _fail("Invalid server host.")
    if len(ascii_host) > 253 or ascii_host.endswith("."):
        _fail("Invalid server host.")
    labels = ascii_host.split(".")
    if any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
        _fail("Invalid server host.")
    return ascii_host.lower()


def _canonical_uuid(value):
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        _fail("Invalid VLESS UUID.")
    return value.lower()


def _canonical_public_key(value):
    if not isinstance(value, str):
        _fail("Invalid REALITY public key.")
    if value.endswith("="):
        if len(value) != 44 or value.count("=") != 1:
            _fail("Invalid REALITY public key.")
        core = value[:-1]
    else:
        if len(value) != 43:
            _fail("Invalid REALITY public key.")
        core = value

    if re.fullmatch(r"[A-Za-z0-9_-]{43}", core):
        encoded = core.replace("-", "+").replace("_", "/")
    elif re.fullmatch(r"[A-Za-z0-9+/]{43}", core):
        encoded = core
    else:
        _fail("Invalid REALITY public key.")

    try:
        decoded = base64.b64decode(encoded + "=", validate=True)
    except (binascii.Error, ValueError):
        _fail("Invalid REALITY public key.")
    if len(decoded) != 32:
        _fail("Invalid REALITY public key.")
    return base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")


def _canonical_short_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}){0,8}", value):
        _fail("Invalid REALITY short ID.")
    return value.lower()


def _canonical_fingerprint(value):
    if not isinstance(value, str) or value.lower() not in _FINGERPRINTS:
        _fail("Invalid REALITY fingerprint.")
    return value.lower()


def _canonical_spider_x(value):
    if not isinstance(value, str) or len(value) > 2048:
        _fail("Invalid REALITY spider path.")
    if value and (
        not value.startswith("/")
        or "\\" in value
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        _fail("Invalid REALITY spider path.")
    return value


def _canonical_port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        _fail("Invalid server port.")
    return value


def _canonical_interface(value):
    if (
        not isinstance(value, str)
        or value in (".", "..")
        or not _INTERFACE_RE.fullmatch(value)
    ):
        _fail("Invalid network interface name.")
    return value


def parse_vless_url(value):
    """Parse a strict VLESS TCP + REALITY + Vision share URL."""
    if not isinstance(value, str) or not value:
        _fail("Invalid VLESS URL.")
    if "\x00" in value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        _fail("Invalid VLESS URL.")

    core = value.split("#", 1)[0]
    if not core or any(character.isspace() for character in core):
        _fail("Invalid VLESS URL.")

    try:
        parsed = urlsplit(value)
    except (TypeError, ValueError):
        _fail("Invalid VLESS URL.")

    if parsed.scheme.lower() != "vless" or parsed.path not in ("", "/"):
        _fail("Invalid VLESS URL.")
    if parsed.netloc.count("@") != 1 or parsed.username is None or parsed.password is not None:
        _fail("Invalid VLESS URL.")
    if "%" in parsed.netloc:
        _fail("Invalid VLESS URL.")

    try:
        server = _canonical_host(parsed.hostname)
        port = _canonical_port(parsed.port)
    except (TypeError, ValueError):
        _fail("Invalid VLESS URL.")

    uuid_value = _canonical_uuid(parsed.username)

    query = parsed.query
    if (
        not query
        or query.startswith("&")
        or query.endswith("&")
        or "&&" in query
        or re.search(r"%(?![0-9A-Fa-f]{2})", query)
    ):
        _fail("Invalid VLESS URL.")
    try:
        pairs = parse_qsl(
            query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=16,
        )
    except (UnicodeError, ValueError):
        _fail("Invalid VLESS URL.")

    parameters = {}
    for key, parameter_value in pairs:
        if not key or key not in _VLESS_QUERY_KEYS or key in parameters:
            _fail("Invalid VLESS URL.")
        parameters[key] = parameter_value

    if (
        parameters.get("type", "tcp") not in ("tcp", "raw")
        or parameters.get("security") != "reality"
        or parameters.get("flow") != "xtls-rprx-vision"
        or parameters.get("encryption", "none") != "none"
        or parameters.get("headerType", "none") != "none"
    ):
        _fail("VLESS URL must use TCP, REALITY, and xtls-rprx-vision.")
    if not all(parameters.get(key) for key in ("sni", "fp", "pbk")):
        _fail("VLESS URL is missing a required REALITY parameter.")

    server_name = _canonical_host(parameters["sni"], require_dns=True)
    fingerprint = _canonical_fingerprint(parameters["fp"])
    public_key = _canonical_public_key(parameters["pbk"])
    short_id = _canonical_short_id(parameters.get("sid", ""))
    spider_x = _canonical_spider_x(parameters.get("spx", ""))

    return {
        "server": server,
        "port": port,
        "uuid": uuid_value,
        "public_key": public_key,
        "server_name": server_name,
        "short_id": short_id,
        "fingerprint": fingerprint,
        "spider_x": spider_x,
    }


def _validated_vless_mapping(vless):
    if not isinstance(vless, dict) or not _VLESS_RESULT_KEYS.issubset(vless):
        _fail("Invalid VLESS configuration.")
    try:
        return {
            "server": _canonical_host(vless["server"]),
            "port": _canonical_port(vless["port"]),
            "uuid": _canonical_uuid(vless["uuid"]),
            "public_key": _canonical_public_key(vless["public_key"]),
            "server_name": _canonical_host(vless["server_name"], require_dns=True),
            "short_id": _canonical_short_id(vless["short_id"]),
            "fingerprint": _canonical_fingerprint(vless["fingerprint"]),
            "spider_x": _canonical_spider_x(vless["spider_x"]),
        }
    except (KeyError, TypeError, ValueError):
        _fail("Invalid VLESS configuration.")


def make_xray_config(vless, server_ipv4, *, ns_interface="ogw-ns", socks_port=10808):
    """Build Xray SOCKS-in / VLESS REALITY-out config for the namespace."""
    parsed = _validated_vless_mapping(vless)
    outer_server = _canonical_ipv4(server_ipv4)
    interface_name = _canonical_interface(ns_interface)
    local_port = _canonical_port(socks_port)
    return {
        "inbounds": [{
            "tag": "socks-in", "listen": "127.0.0.1", "port": local_port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
        }],
        "outbounds": [{
            "tag": "vless-out", "protocol": "vless",
            "settings": {
                "address": outer_server, "port": parsed["port"], "id": parsed["uuid"],
                "encryption": "none",
                # Xray removes this client-only suffix on the wire; it permits WireGuard UDP/443.
                "flow": "xtls-rprx-vision-udp443",
            },
            "streamSettings": {
                "method": "raw", "security": "reality",
                "realitySettings": {
                    "serverName": parsed["server_name"], "fingerprint": parsed["fingerprint"],
                    "password": parsed["public_key"], "shortId": parsed["short_id"],
                    "spiderX": parsed["spider_x"],
                },
                "sockopt": {"interface": interface_name},
            },
        }],
    }


def make_sing_config(server_ipv4, *, socks_port=10808):
    """Build the sing-box TUN-to-local-Xray-SOCKS configuration."""
    outer_server = _canonical_ipv4(server_ipv4)
    local_port = _canonical_port(socks_port)

    return {
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "ogw-tun",
                # Targets the unified TUN address schema (sing-box 1.12+).
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "auto_redirect": True,
                "route_exclude_address": [outer_server + "/32", VETH_NET],
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "xray-socks",
                "server": "127.0.0.1",
                "server_port": local_port,
                "version": "5",
                "bind_interface": "lo",
                # Omitting "network" keeps both TCP and UDP enabled.
            }
        ],
        "route": {"final": "xray-socks"},
    }

SING_VERSION = "1.14.4"
XRAY_VERSION = "26.10.21"
GITHUB_API = "https://api.github.com/repos/{repository}/releases/tags/{tag}"
MAX_DOWNLOAD = 200 * 1024 * 1024
RELEASE_SHA256 = {
    "sing-box-1.14.4-linux-amd64-glibc.tar.gz": "231e57c18378f780a08de832844a1ca9716e17a7bcf82964b350844d243c03ac",
    "sing-box-1.14.4-linux-arm64-glibc.tar.gz": "241cb4ccbf1a003235f8a969cc25d28cc74487df52721f6de28be7e37eae2ae9",
    "Xray-linux-64.zip": "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978",
    "Xray-linux-arm64-v8a.zip": "d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c",
}


def architecture():
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64", "64"
    if machine in ("aarch64", "arm64"):
        return "arm64", "arm64-v8a"
    raise OuterError("Only Linux x86-64 and ARM64 releases are supported.")


def _urlopen(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "outer-vpn-installer/1",
        "Accept": "application/vnd.github+json",
    })
    try:
        return urllib.request.urlopen(request, timeout=60)
    except (urllib.error.URLError, OSError) as exc:
        raise OuterError("Could not download official release information.") from exc


def _get_bytes(url, limit):
    try:
        with _urlopen(url) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > limit:
                raise OuterError("A release download exceeded its size limit.")
            data = response.read(limit + 1)
    except (OSError, ValueError) as exc:
        raise OuterError("Could not read an official release download.") from exc
    if len(data) > limit:
        raise OuterError("A release download exceeded its size limit.")
    return data


def release_asset(repository, tag, asset_name):
    url = GITHUB_API.format(repository=repository, tag=tag)
    try:
        metadata = json.loads(_get_bytes(url, 4 * 1024 * 1024))
    except (ValueError, TypeError) as exc:
        raise OuterError("The official release metadata was invalid.") from exc
    if metadata.get("tag_name") != tag or metadata.get("prerelease") or metadata.get("draft"):
        raise OuterError("The official release metadata did not match the pinned release.")
    matches = [asset for asset in metadata.get("assets", []) if asset.get("name") == asset_name]
    if len(matches) != 1:
        raise OuterError("The official release does not contain the expected asset.")
    digest = matches[0].get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise OuterError("The official release has no usable SHA-256 checksum.")
    if RELEASE_SHA256.get(asset_name) != digest[7:]:
        raise OuterError("The official checksum differs from the pinned release checksum.")
    expected_url = f"https://github.com/{repository}/releases/download/{tag}/{asset_name}"
    if matches[0].get("browser_download_url") != expected_url:
        raise OuterError("The official release asset URL did not match the pinned release.")
    return expected_url, digest.removeprefix("sha256:")


def _verified_download(repository, tag, asset):
    url, expected = release_asset(repository, tag, asset)
    data = _get_bytes(url, MAX_DOWNLOAD)
    if hashlib.sha256(data).hexdigest() != expected:
        raise OuterError("An official release failed SHA-256 verification.")
    return data


def _extract_sing(archive):
    import io
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            matches = [m for m in tar.getmembers() if Path(m.name).name == "sing-box" and m.isfile()]
            if len(matches) != 1 or matches[0].size <= 0 or matches[0].size > MAX_DOWNLOAD:
                raise OuterError("The sing-box archive did not contain one valid binary.")
            stream = tar.extractfile(matches[0])
            if stream is None:
                raise OuterError("The sing-box binary could not be read.")
            return stream.read(MAX_DOWNLOAD + 1)
    except (tarfile.TarError, OSError) as exc:
        raise OuterError("The sing-box archive was invalid.") from exc


def _extract_xray(archive):
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            matches = [item for item in zipped.infolist() if item.filename == "xray" and not item.is_dir()]
            if len(matches) != 1 or matches[0].file_size <= 0 or matches[0].file_size > MAX_DOWNLOAD:
                raise OuterError("The Xray archive did not contain one valid binary.")
            file_type = stat.S_IFMT(matches[0].external_attr >> 16)
            if file_type not in (0, stat.S_IFREG):
                raise OuterError("The Xray archive did not contain a regular binary.")
            return zipped.read(matches[0])
    except (zipfile.BadZipFile, OSError) as exc:
        raise OuterError("The Xray archive was invalid.") from exc


def download_binaries(confirmed=False, runner=RUNNER):
    sing_arch, xray_arch = architecture()
    print(f"Official releases: sing-box {SING_VERSION}, Xray {XRAY_VERSION} ({sing_arch}).")
    if not confirmed:
        try:
            answer = input("Download these official releases and verify their SHA-256 checksums? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            raise OuterError("Download cancelled; nothing was installed.")
    sing_asset = f"sing-box-{SING_VERSION}-linux-{sing_arch}-glibc.tar.gz"
    xray_asset = f"Xray-linux-{xray_arch}.zip"
    sing = _extract_sing(_verified_download("SagerNet/sing-box", f"v{SING_VERSION}", sing_asset))
    xray = _extract_xray(_verified_download("XTLS/Xray-core", f"v{XRAY_VERSION}", xray_asset))
    with tempfile.TemporaryDirectory(prefix="outer-vpn-release-") as temporary:
        for name, data, version_args in (("sing-box", sing, ["version"]), ("xray", xray, ["version"])):
            executable = Path(temporary) / name
            atomic_write(executable, data, 0o755)
            runner.run([str(executable), *version_args], timeout=30)
    return sing, xray


def _file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def installed_binary_integrity(paths=PATHS):
    try:
        data = json.loads(paths.manifest.read_text(encoding="utf-8"))
        return (
            data["sing_version"] == SING_VERSION and data["xray_version"] == XRAY_VERSION
            and data["sing_sha256"] == _file_digest(paths.sing)
            and data["xray_sha256"] == _file_digest(paths.xray)
        )
    except (OSError, KeyError, ValueError, TypeError):
        return False


def install(paths=PATHS, runner=RUNNER, *, confirmed=False, source=None, env_path=".env"):
    require_root()
    source = Path(source or __file__).resolve()
    script = source.read_bytes()
    unit = service_unit().encode()
    binaries_ok = installed_binary_integrity(paths)
    same_script = paths.script.is_file() and paths.script.read_bytes() == script
    same_unit = paths.unit.is_file() and paths.unit.read_bytes() == unit
    legacy = legacy_paths(paths)
    if binaries_ok and same_script and same_unit:
        if legacy:
            print("Installation is current; the legacy setup will be backed up and migrated at start.")
        else:
            print("Installation is already current.")
        return
    if systemd_active(runner):
        raise OuterError("Stop the active gateway before changing its installation.")
    settings = read_settings(env_path)
    register_settings_secrets(settings, runner)
    server = checked_server(settings)
    prepare_nft_rules(settings, server, runner)
    if binaries_ok:
        sing, xray = paths.sing.read_bytes(), paths.xray.read_bytes()
    else:
        sing, xray = download_binaries(confirmed=confirmed, runner=runner)
    tx = FileTransaction(paths, "install")
    try:
        for item in legacy:
            tx.snapshot(item)
        if not binaries_ok:
            tx.write(paths.sing, sing, 0o755)
            tx.write(paths.xray, xray, 0o755)
        tx.write(paths.script, script, 0o755)
        tx.write(paths.unit, unit, 0o644)
        manifest = {
            "sing_version": SING_VERSION, "xray_version": XRAY_VERSION,
            "sing_sha256": hashlib.sha256(sing).hexdigest(),
            "xray_sha256": hashlib.sha256(xray).hexdigest(),
        }
        tx.write(paths.manifest, (json.dumps(manifest, sort_keys=True) + "\n").encode(), 0o644)
        runner.run(["systemctl", "daemon-reload"])
    except BaseException:
        tx.rollback()
        with contextlib.suppress(OuterError):
            runner.run(["systemctl", "daemon-reload"])
        raise
    print(f"Installed. Backup: {tx.directory}")
    if legacy:
        print("Legacy files were backed up and remain active until the protected start transition.")


def _settings_from_values(values):
    if not values.get("VLESS_URL") or not values.get("PROTON_ENDPOINTS"):
        raise ValueError("VLESS_URL and PROTON_ENDPOINTS are required.")
    vless = parse_vless_url(values["VLESS_URL"])
    endpoints = parse_proton_endpoints(values["PROTON_ENDPOINTS"])
    if not endpoints:
        raise ValueError("At least one Proton IPv4 endpoint is required.")
    interface = validate_interface(values.get("PROTON_INTERFACE", DEFAULT_PROTON_INTERFACE))
    dns = validate_dns(values.get("DNS_SERVER", DEFAULT_DNS))
    strict = values.get("STRICT_MODE", "false").strip().lower()
    if strict not in ("true", "false"):
        raise ValueError("STRICT_MODE must be true or false.")
    return {"vless": vless, "endpoints": endpoints, "interface": interface, "dns": dns,
            "strict": strict == "true"}


def read_settings_and_data(env_path):
    try:
        data = Path(env_path).read_bytes()
        text = data.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ValueError("Unable to read environment file.") from exc
    return _settings_from_values(parse_env_text(text)), data


def read_settings(env_path):
    return read_settings_and_data(env_path)[0]


def checked_server(settings):
    server = resolve_ipv4(settings["vless"]["server"], settings["vless"]["port"])
    if server in settings["endpoints"] or server == settings["dns"]:
        raise OuterError("The outer server, Proton endpoints and probe DNS server must be distinct.")
    if ipaddress.IPv4Address(server) in ipaddress.IPv4Network(VETH_NET):
        raise OuterError("The outer server conflicts with the gateway network.")
    return server


def validate_configs(settings, server, paths=PATHS, runner=RUNNER):
    register_settings_secrets(settings, runner)
    if not installed_binary_integrity(paths):
        raise OuterError("Install verified sing-box and Xray binaries first.")
    with tempfile.TemporaryDirectory(prefix="outer-vpn-config-") as temporary:
        directory = Path(temporary)
        xray = directory / "xray.json"
        sing = directory / "sing-box.json"
        atomic_json(xray, make_xray_config(settings["vless"], server, ns_interface=NS_IF, socks_port=SOCKS_PORT))
        atomic_json(sing, make_sing_config(server, socks_port=SOCKS_PORT))
        runner.run([str(paths.xray), "run", "-test", "-config", str(xray)], timeout=30)
        runner.run([str(paths.sing), "check", "-c", str(sing)], timeout=30)


def apply_config(env_path, paths=PATHS, runner=RUNNER):
    require_root()
    settings, data = read_settings_and_data(env_path)
    server = checked_server(settings)
    validate_configs(settings, server, paths, runner)
    unchanged = not paths.env.is_symlink() and paths.env.is_file() and paths.env.read_bytes() == data
    secure_mode = (unchanged and stat.S_IMODE(paths.env.stat().st_mode) == 0o600
                   and paths.env.stat().st_uid == 0)
    if unchanged and secure_mode:
        print("Configuration is already applied and validated.")
        return
    if systemd_active(runner):
        raise OuterError("Stop the active gateway before changing its configuration.")
    tx = FileTransaction(paths, "apply")
    try:
        tx.write(paths.env, data, 0o600)
    except BaseException:
        tx.rollback()
        raise
    print(f"Configuration validated and applied. Backup: {tx.directory}")


def save_state(state, paths=PATHS):
    _ensure_dir(paths.runtime, 0o700)
    os.chmod(paths.runtime, 0o700)
    atomic_json(paths.state, state)


def load_state(paths=PATHS):
    if not paths.state.exists():
        return None
    try:
        state = json.loads(paths.state.read_text(encoding="utf-8"))
        if state.get("version") != 1 or not isinstance(state.get("undo"), list):
            raise ValueError
        return state
    except PermissionError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise OuterError("The gateway recovery journal is invalid; do not remove the firewall manually.") from exc


def journal_action(state, undo, *, protected=False, kind="command", paths=PATHS):
    item = {"kind": kind, "value": undo, "protected": protected}
    state["undo"].append(item)
    save_state(state, paths)
    return item


def journal_failure(state, error, *, paths=PATHS, runner=RUNNER):
    message = redact_text(error, getattr(runner, "secrets", ()))
    state["last_error"] = message
    errors = state.setdefault("errors", [])
    if not errors or errors[-1] != message:
        errors.append(message)
        del errors[:-10]
    save_state(state, paths)
    return message


def log_failure(message, runner=RUNNER):
    safe = redact_text(message, getattr(runner, "secrets", ()))
    try:
        syslog.openlog("outer-vpn", syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_ERR, safe)
    except OSError:
        pass


def _already_absent(result):
    message = result.stderr.lower()
    return any(phrase in message for phrase in (
        "no such process", "no such file", "no such device", "cannot find device",
        "does not exist", "cannot open network namespace", "no such table", "link not found",
    ))


def _undo_one(item, runner=RUNNER):
    kind, value = item["kind"], item["value"]
    if kind == "file":
        remove_path(Path(value))
        return
    if kind == "restore_route":
        current = runner.json(["ip", "-j", "-4", "route", "show", "table", "main", "default"])
        if any(_same_route(route, value) for route in current):
            return
        runner.run(["ip", "-4", "route", "add", *_route_args(value)])
        return
    if kind == "restore_sysctl":
        key, previous = value
        result = runner.run(["sysctl", "-n", key], check=False)
        if result.returncode:
            if _already_absent(result):
                return
            raise command_failure(getattr(result, "args", ["sysctl", "-n", key]), result.returncode, result.stderr,
                                  secrets=getattr(runner, "secrets", ()), label="Could not restore forwarding")
        if result.stdout.strip() == "1" and previous != "1":
            runner.run(["sysctl", "-w", f"{key}={previous}"])
        return
    result = runner.run(value, check=False)
    if result.returncode and not _already_absent(result):
        args = getattr(result, "args", value)
        raise command_failure(args, result.returncode, result.stderr,
                              secrets=getattr(runner, "secrets", ()), label="Could not undo command")


def cleanup(state=None, *, preserve_guard=False, preserve_journal=False, paths=PATHS, runner=RUNNER):
    preserve_guard = preserve_guard or (paths.runtime / "hold-guard").exists()
    state = state if state is not None else load_state(paths)
    if not state:
        return
    errors = []
    for item in reversed(state["undo"][:]):
        if item.get("protected"):
            continue
        try:
            _undo_one(item, runner)
            state["undo"].remove(item)
            save_state(state, paths)
        except (OSError, OuterError) as exc:
            errors.append(str(exc))
    if not preserve_guard:
        for item in reversed(state["undo"][:]):
            if not item.get("protected"):
                continue
            try:
                _undo_one(item, runner)
                state["undo"].remove(item)
                save_state(state, paths)
            except (OSError, OuterError) as exc:
                errors.append(str(exc))
    if errors:
        state["phase"] = "cleanup-incomplete"
        detail = "\n".join(errors)
        journal_failure(state, detail, paths=paths, runner=runner)
        raise OuterError("Cleanup was incomplete; run stop again.\n" + detail)
    if state["undo"] or preserve_journal:
        state["phase"] = "cleanup-incomplete" if preserve_journal else "failed-guarded"
        save_state(state, paths)
    else:
        with contextlib.suppress(FileNotFoundError):
            paths.state.unlink()
        for name in ("xray.json", "sing-box.json"):
            with contextlib.suppress(FileNotFoundError):
                (paths.runtime / name).unlink()
        with contextlib.suppress(OSError):
            paths.runtime.rmdir()


def _action(state, command, undo, *, protected=False, kind="command", paths=PATHS, runner=RUNNER, input_text=None):
    journal_action(state, undo, protected=protected, kind=kind, paths=paths)
    try:
        runner.run(command, input_text=input_text)
    except OuterError as exc:
        journal_failure(state, str(exc), paths=paths, runner=runner)
        raise


def _transition_script():
    return '''table inet outer_vpn_transition {
  chain output {
    type filter hook output priority -300; policy accept;
    oifname "lo" accept
    counter drop
  }
}
'''


def _nft_tables(runner=RUNNER):
    data = runner.json(["nft", "-j", "list", "tables"])
    return {(entry["table"]["family"], entry["table"]["name"])
            for entry in data.get("nftables", []) if "table" in entry}


def _active_guards(runner=RUNNER):
    return sorted(name for family, name in _nft_tables(runner)
                  if family == "inet" and name in ("outer_vpn_transition", "outer_vpn_guard"))


def add_transition(state, paths=PATHS, runner=RUNNER):
    if ("inet", "outer_vpn_transition") in _nft_tables(runner):
        raise OuterError("The reserved transition firewall already exists.")
    _action(state, ["nft", "-f", "-"], ["nft", "delete", "table", "inet", "outer_vpn_transition"],
            protected=True, paths=paths, runner=runner, input_text=_transition_script())


def drop_transition(state, paths=PATHS, runner=RUNNER):
    target = ["nft", "delete", "table", "inet", "outer_vpn_transition"]
    item = next((item for item in state["undo"] if item["value"] == target), None)
    if item:
        _undo_one(item, runner)
        state["undo"].remove(item)
        save_state(state, paths)


def _route_args(route):
    if route.get("type", "unicast") not in ("unicast", "") or "multipath" in route or "nexthops" in route or "nhid" in route:
        raise OuterError("An existing default route is unsupported; no route was changed.")
    if not route.get("dev"):
        raise OuterError("An existing default route has no interface; no route was changed.")
    args = ["default"]
    if route.get("gateway"):
        args += ["via", route["gateway"]]
    args += ["dev", route["dev"]]
    if route.get("protocol"):
        args += ["proto", str(route["protocol"])]
    if route.get("scope"):
        args += ["scope", str(route["scope"])]
    if route.get("prefsrc"):
        args += ["src", route["prefsrc"]]
    if "metric" in route:
        args += ["metric", str(route["metric"])]
    if "onlink" in route.get("flags", []):
        args.append("onlink")
    supported = {"dst", "gateway", "dev", "protocol", "scope", "prefsrc", "metric", "flags", "type", "table"}
    if set(route) - supported:
        raise OuterError("An existing default route has unsupported attributes; no route was changed.")
    return args


def _same_route(a, b):
    fields = ("dst", "gateway", "dev", "metric", "protocol", "scope", "prefsrc")
    return (all(a.get(key, 0 if key == "metric" else None) == b.get(key, 0 if key == "metric" else None)
                for key in fields)
            and ("onlink" in a.get("flags", [])) == ("onlink" in b.get("flags", [])))


def _route_prefix(route):
    destination = route.get("dst", "default")
    if destination == "default":
        return ipaddress.IPv4Network("0.0.0.0/0")
    try:
        return ipaddress.IPv4Network(destination, strict=False)
    except ValueError:
        return None


def detect_outer_route(server, interface, runner=RUNNER):
    selection = runner.json(["ip", "-j", "-4", "route", "get", server])
    if not selection or not selection[0].get("dev"):
        raise OuterError("No physical IPv4 route to the outer server is available.")
    selected = selection[0]
    device = validate_interface(selected["dev"])
    if device == interface or device.startswith(("proton", "pvpn")):
        raise OuterError("The outer server currently routes through Proton; disconnect it before starting.")
    return selected


def network_inventory(server, endpoints, interface, runner=RUNNER):
    names = runner.run(["ip", "netns", "list"]).stdout.splitlines()
    if any(line.split()[0] == NAMESPACE for line in names if line.split()):
        raise OuterError("The reserved network namespace already exists.")
    for name in (HOST_IF, NS_IF):
        if runner.run(["ip", "link", "show", "dev", name], check=False).returncode == 0:
            raise OuterError("A reserved gateway interface already exists.")
    tables = _nft_tables(runner)
    if ("inet", "outer_vpn_guard") in tables or ("ip", "outer_vpn_nat") in tables:
        raise OuterError("A reserved firewall table already exists.")
    for family, priority in (("-4", RULE_ENDPOINT), ("-4", RULE_SOURCE), ("-4", RULE_SOURCE_DROP), ("-6", RULE_IPV6)):
        rules = runner.json(["ip", "-j", family, "rule", "show"])
        if any(str(rule.get("priority", rule.get("pref", ""))) == priority for rule in rules):
            raise OuterError("A reserved policy-routing priority is already in use.")
    for family, table in (("-4", ROUTE_TABLE), ("-4", PROTON_TABLE), ("-6", IPV6_TABLE)):
        result = runner.run(["ip", "-j", family, "route", "show", "table", table], check=False)
        if result.returncode:
            if "table does not exist" not in result.stderr.lower() and "no such" not in result.stderr.lower():
                raise command_failure(getattr(result, "args", ["ip", "-j", family, "route", "show", "table", table]),
                                      result.returncode, result.stderr, secrets=getattr(runner, "secrets", ()),
                                      label="Could not inspect routing table")
        elif json.loads(result.stdout or "[]"):
            raise OuterError("A reserved routing table is already in use.")
    routes = runner.json(["ip", "-j", "-4", "route", "show", "table", "main"])
    veth = ipaddress.IPv4Network(VETH_NET)
    for route in routes:
        prefix = _route_prefix(route)
        if prefix and prefix.prefixlen and prefix.overlaps(veth):
            raise OuterError("The gateway veth subnet conflicts with an existing route.")
        if prefix and prefix.prefixlen == 32 and str(prefix.network_address) in endpoints:
            raise OuterError("A Proton endpoint already has a host route; it was not changed.")
    for link in runner.json(["ip", "-j", "address", "show"]):
        for address in link.get("addr_info", []):
            if address.get("family") == "inet":
                network = ipaddress.IPv4Network(f"{address['local']}/{address['prefixlen']}", strict=False)
                if network.overlaps(veth):
                    raise OuterError("The gateway veth subnet conflicts with an existing address.")
    defaults = [route for route in routes if route.get("dst") == "default"]
    for route in defaults:
        _route_args(route)
        device = route.get("dev", "")
        if device == interface or device.startswith(("proton", "pvpn")):
            raise OuterError("A Proton route is active; connect Proton only after the outer gateway starts.")
    selected = detect_outer_route(server, interface, runner)
    device = selected["dev"]
    outer_routes = [route for route in routes if _route_prefix(route) == ipaddress.IPv4Network(f"{server}/32")]
    if outer_routes and any(route.get("dev") != device or route.get("gateway") != selected.get("gateway") for route in outer_routes):
        raise OuterError("An existing outer-server host route conflicts with the gateway.")
    return {"defaults": defaults, "physical": device, "gateway": selected.get("gateway"),
            "outer_route_exists": bool(outer_routes)}


def _guard_script(settings, server, physical):
    # WireGuard's message prefix prevents the UDP peer exception from carrying normal QUIC.
    # OUTPUT already has a selected oif; nft FIB oif results are not supported there.
    bootstrap = "" if settings.get("strict", False) else f' elements = {{ "{HOST_IF}" }};'
    return f'''table inet outer_vpn_guard {{
  set proton_ifaces {{ type ifname; }}
  set proton_peers {{ type ipv4_addr . inet_service; }}
  set bootstrap_ifaces {{ type ifname;{bootstrap} }}
  chain output {{
    type filter hook output priority -150; policy accept;
    oifname "lo" accept
    meta nfproto ipv6 counter drop
    oifname @proton_ifaces accept
    oifname "{HOST_IF}" ip daddr . udp dport @proton_peers @th,64,32 {{ 0x01000000, 0x02000000, 0x03000000, 0x04000000 }} accept
    oifname @bootstrap_ifaces accept
    counter drop
  }}
  chain forward {{
    type filter hook forward priority -150; policy accept;
    iifname "{HOST_IF}" oifname "{physical}" ip saddr {NS_IP} ip daddr {server} tcp dport {settings['vless']['port']} accept
    iifname "{HOST_IF}" counter drop
    oifname "{HOST_IF}" iifname "{physical}" ip saddr {server} ip daddr {NS_IP} ct state established,related accept
    oifname "{HOST_IF}" counter drop
  }}
}}
table ip outer_vpn_nat {{
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "{physical}" ip saddr {NS_IP} ip daddr {server} tcp dport {settings['vless']['port']} masquerade
  }}
}}
'''


def _proton_guard_script(settings, peers, latched):
    script = ("flush set inet outer_vpn_guard proton_ifaces\n"
              "flush set inet outer_vpn_guard proton_peers\n"
              "flush set inet outer_vpn_guard bootstrap_ifaces\n")
    if not latched and not settings.get("strict", False):
        script += f'add element inet outer_vpn_guard bootstrap_ifaces {{ "{HOST_IF}" }}\n'
    if peers:
        elements = ", ".join(f"{address} . {port}" for address, port in peers)
        script += f'add element inet outer_vpn_guard proton_peers {{ {elements} }}\n'
        script += f'add element inet outer_vpn_guard proton_ifaces {{ "{settings["interface"]}" }}\n'
    return script


def nft_rule_plan(settings, server, physical):
    guard = _guard_script(settings, server, physical)
    peer = ((settings["endpoints"][0], 51820),)
    updates = [
        ("waiting for Proton", _proton_guard_script(settings, (), False)),
        ("peer configured", _proton_guard_script(settings, peer, False)),
        ("Proton connected", _proton_guard_script(settings, peer, True)),
        ("Proton disconnected", _proton_guard_script(settings, (), True)),
    ]
    checks = [("transition", _transition_script()), ("guard and NAT", guard)]
    checks.extend((label, guard + script) for label, script in updates)
    checks.append(("transition deletion", _transition_script() +
                   "delete table inet outer_vpn_transition\n"))
    checks.append(("guard and NAT deletion", guard +
                   "delete table inet outer_vpn_guard\ndelete table ip outer_vpn_nat\n"))
    return {"checks": checks, "transition": _transition_script(), "guard": guard, "updates": updates}


def _inert_nft_script(script, names):
    for original, replacement in names.items():
        script = re.sub(r"\b" + re.escape(original) + r"\b", replacement, script)
    lines = []
    in_chain = False
    for line in script.splitlines():
        stripped = line.strip()
        if line.startswith("  chain ") and stripped.endswith("{"):
            in_chain = True
        elif in_chain and line == "  }":
            in_chain = False
        elif in_chain and stripped:
            if stripped.startswith("type "):
                if "policy accept;" not in stripped:
                    raise OuterError("The nft preflight requires an accept chain policy.")
            else:
                # Both comparisons inspect the same packet mark, so no probe rule can match.
                rule = re.sub(r"\bdrop$", "accept", stripped)
                line = "    meta mark 0x0 meta mark != 0x0 " + rule
        lines.append(line)
    return "\n".join(lines) + "\n"


def nft_kernel_plan(settings, server, physical, token):
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise OuterError("The nft preflight table identifier is invalid.")
    names = {"outer_vpn_transition": f"ogw_probe_t_{token}",
             "outer_vpn_guard": f"ogw_probe_g_{token}",
             "outer_vpn_nat": f"ogw_probe_n_{token}"}
    base = nft_rule_plan(settings, server, physical)
    setup = _inert_nft_script(base["transition"], names) + _inert_nft_script(base["guard"], names)
    updates = [(label, _inert_nft_script(script, names)) for label, script in base["updates"]]
    tables = [("inet", names["outer_vpn_transition"]), ("inet", names["outer_vpn_guard"]),
              ("ip", names["outer_vpn_nat"])]
    return {"setup": setup, "updates": updates, "tables": tables}


def run_nft_kernel_probe(plan, runner=RUNNER):
    _require_new_network_namespace()
    planned = {tuple(table) for table in plan["tables"]}
    if _nft_tables(runner) & planned:
        raise OuterError("A temporary nft preflight table already exists in the probe namespace.")
    failure = None
    cleanup_errors = []
    try:
        runner.run(["nft", "-f", "-"], input_text=plan["setup"])
        for label, script in plan["updates"]:
            try:
                runner.run(["nft", "-f", "-"], input_text=script)
            except OuterError as exc:
                raise OuterError(f"nft kernel preflight failed for {label}:\n{exc}") from exc
    except BaseException as exc:
        failure = exc
    finally:
        for family, name in reversed(plan["tables"]):
            command = ["nft", "delete", "table", family, name]
            try:
                result = runner.run(command, check=False)
                if result.returncode and not _already_absent(result):
                    cleanup_errors.append(str(command_failure(getattr(result, "args", command), result.returncode,
                                                              result.stderr, secrets=getattr(runner, "secrets", ()))))
            except (OuterError, OSError) as exc:
                cleanup_errors.append(str(exc))
    if cleanup_errors:
        message = "Could not remove an nft preflight table:\n" + "\n".join(cleanup_errors)
        if failure:
            message = str(failure) + "\n" + message
        raise OuterError(message) from failure
    if failure:
        raise failure


def _require_new_network_namespace():
    try:
        current = os.stat("/proc/self/ns/net")
        parent = os.stat(f"/proc/{os.getppid()}/ns/net")
    except OSError as exc:
        raise OuterError("Could not verify the isolated nft preflight namespace.") from exc
    if (current.st_dev, current.st_ino) == (parent.st_dev, parent.st_ino):
        raise OuterError("The nft kernel preflight must run in a new network namespace.")


def validate_nft_rules(settings, server, physical, runner=RUNNER):
    for label, script in nft_rule_plan(settings, server, physical)["checks"]:
        try:
            runner.run(["nft", "-c", "-f", "-"], input_text=script)
        except OuterError as exc:
            raise OuterError(f"nft pre-validation failed for {label}:\n{exc}") from exc
    plan = nft_kernel_plan(settings, server, physical, uuid.uuid4().hex)
    command = ["unshare", "--net", "--", sys.executable, str(Path(__file__).resolve()), "_nft-kernel-probe"]
    try:
        runner.run(command, input_text=json.dumps(plan), timeout=90)
    except OuterError as exc:
        raise OuterError(f"nft kernel preflight failed:\n{exc}") from exc


def prepare_nft_rules(settings, server, runner=RUNNER):
    route = detect_outer_route(server, settings["interface"], runner)
    reserved = {("inet", "outer_vpn_transition"), ("inet", "outer_vpn_guard"),
                ("ip", "outer_vpn_nat")}
    if _nft_tables(runner) & reserved:
        raise OuterError("A reserved nftables table already exists; inspect status before starting.")
    validate_nft_rules(settings, server, route["dev"], runner)
    return route["dev"]


def debug_rules(env_path, runner=RUNNER):
    settings = read_settings(env_path)
    register_settings_secrets(settings, runner)
    server = checked_server(settings)
    route = detect_outer_route(server, settings["interface"], runner)
    physical = route["dev"]
    plan = nft_rule_plan(settings, server, physical)
    nft = executable_path("nft")
    print(f"Detected outer-server interface: {physical}")
    print("Only read-only inspection was performed; no network settings were changed.")
    print("Peer-update examples use a configured endpoint and illustrative UDP port 51820.")
    try:
        tables = _nft_tables(runner)
        present = sorted(name for family, name in tables if (family, name) in {
            ("inet", "outer_vpn_transition"), ("inet", "outer_vpn_guard"), ("ip", "outer_vpn_nat")})
        print("Existing reserved tables: " + (", ".join(present) if present else "none"))
    except OuterError as exc:
        print(f"Existing reserved tables: unknown ({exc})")
    print("\n# Inspect existing tables\n" + shlex.join([nft, "-j", "list", "tables"]))
    for label, script in plan["checks"]:
        print(f"\n# Read-only validation: {label}\n" + shlex.join([nft, "-c", "-f", "-"]))
        print(script, end="" if script.endswith("\n") else "\n")
    probe = nft_kernel_plan(settings, server, physical, uuid.uuid4().hex)
    unshare = executable_path("unshare")
    print("\n# Kernel preflight runs in a new network namespace; table names are examples")
    print(shlex.join([unshare, "--net", "--", sys.executable, str(Path(__file__).resolve()), "_nft-kernel-probe"]))
    print("\n# Inspect tables in the preflight namespace\n" + shlex.join([nft, "-j", "list", "tables"]))
    for label, script in [("temporary setup", probe["setup"]), *probe["updates"]]:
        print(f"\n# Kernel preflight: {label}\n" + shlex.join([nft, "-f", "-"]))
        print(script, end="" if script.endswith("\n") else "\n")
    for family, name in reversed(probe["tables"]):
        print("\n# Delete temporary preflight table\n" + shlex.join([nft, "delete", "table", family, name]))
    for label, script in [("transition", plan["transition"]), ("guard and NAT", plan["guard"]), *plan["updates"]]:
        print(f"\n# Apply: {label}\n" + shlex.join([nft, "-f", "-"]))
        print(script, end="" if script.endswith("\n") else "\n")
    for family, name in (("inet", "outer_vpn_transition"), ("ip", "outer_vpn_nat"),
                         ("inet", "outer_vpn_guard")):
        print("\n# Remove owned table\n" + shlex.join([nft, "delete", "table", family, name]))


def _set_forwarding(state, interface, *, paths=PATHS, runner=RUNNER):
    # Per-interface forwarding avoids the global ip_forward reset of host IPv4 settings.
    key = f"net/ipv4/conf/{interface}/forwarding"
    previous = runner.run(["sysctl", "-n", key]).stdout.strip()
    if previous not in ("0", "1"):
        raise OuterError("An interface forwarding setting could not be inspected.")
    if previous != "1":
        journal_action(state, [key, previous], kind="restore_sysctl", paths=paths)
        runner.run(["sysctl", "-w", f"{key}=1"])


def _write_runtime_config(state, settings, server, paths=PATHS):
    for name, data in (("xray.json", make_xray_config(settings["vless"], server, ns_interface=NS_IF, socks_port=SOCKS_PORT)),
                       ("sing-box.json", make_sing_config(server, socks_port=SOCKS_PORT))):
        target = paths.runtime / name
        journal_action(state, str(target), kind="file", paths=paths)
        atomic_json(target, data)


def _network_before_cores(state, settings, server, inventory, paths=PATHS, runner=RUNNER):
    physical, gateway = inventory["physical"], inventory["gateway"]
    _action(state, ["ip", "netns", "add", NAMESPACE], ["ip", "netns", "delete", NAMESPACE], paths=paths, runner=runner)
    _action(state, ["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", NS_IF],
            ["ip", "link", "delete", HOST_IF], paths=paths, runner=runner)
    for command in (
        ["ip", "link", "set", NS_IF, "netns", NAMESPACE],
        ["ip", "address", "add", f"{HOST_IP}/30", "dev", HOST_IF],
        ["ip", "link", "set", HOST_IF, "up"],
        ["ip", "-n", NAMESPACE, "link", "set", "lo", "up"],
        ["ip", "-n", NAMESPACE, "address", "add", f"{NS_IP}/30", "dev", NS_IF],
        ["ip", "-n", NAMESPACE, "link", "set", NS_IF, "up"],
        ["ip", "-n", NAMESPACE, "route", "add", "default", "via", HOST_IP, "dev", NS_IF],
        ["ip", "netns", "exec", NAMESPACE, "sysctl", "-w", "net.ipv4.ip_forward=1"],
    ):
        runner.run(command)
    _set_forwarding(state, HOST_IF, paths=paths, runner=runner)
    _set_forwarding(state, physical, paths=paths, runner=runner)
    via = (["via", gateway] if gateway else []) + ["dev", physical]
    if not inventory["outer_route_exists"]:
        cmd = ["ip", "-4", "route", "add", f"{server}/32", *via, "metric", "0", "proto", MANAGED_ROUTE_PROTO]
        undo = ["ip", "-4", "route", "del", f"{server}/32", *via, "metric", "0", "proto", MANAGED_ROUTE_PROTO]
        _action(state, cmd, undo, paths=paths, runner=runner)
    _action(state, ["ip", "-4", "route", "add", "table", ROUTE_TABLE, f"{server}/32", *via],
            ["ip", "-4", "route", "del", "table", ROUTE_TABLE, f"{server}/32", *via], paths=paths, runner=runner)
    _action(state, ["ip", "-4", "rule", "add", "priority", RULE_SOURCE, "from", f"{NS_IP}/32", "lookup", ROUTE_TABLE],
            ["ip", "-4", "rule", "del", "priority", RULE_SOURCE, "from", f"{NS_IP}/32", "lookup", ROUTE_TABLE], paths=paths, runner=runner)
    _action(state, ["ip", "-4", "rule", "add", "priority", RULE_SOURCE_DROP, "from", f"{NS_IP}/32", "prohibit"],
            ["ip", "-4", "rule", "del", "priority", RULE_SOURCE_DROP, "from", f"{NS_IP}/32", "prohibit"], paths=paths, runner=runner)
    # A failure in either table creation must still remove both tables during rollback.
    journal_action(state, ["nft", "delete", "table", "inet", "outer_vpn_guard"], protected=True, paths=paths)
    journal_action(state, ["nft", "delete", "table", "ip", "outer_vpn_nat"], paths=paths)
    runner.run(["nft", "-f", "-"], input_text=_guard_script(settings, server, physical))
    _write_runtime_config(state, settings, server, paths)


def _network_after_probe(state, settings, inventory, paths=PATHS, runner=RUNNER):
    for endpoint in settings["endpoints"]:
        prefix = f"{endpoint}/32"
        _action(state, ["ip", "-4", "route", "add", "blackhole", prefix, "metric", BLACKHOLE_METRIC],
                ["ip", "-4", "route", "del", "blackhole", prefix, "metric", BLACKHOLE_METRIC],
                protected=True, paths=paths, runner=runner)
        _action(state, ["ip", "-4", "route", "add", "table", PROTON_TABLE, "blackhole", prefix, "metric", BLACKHOLE_METRIC],
                ["ip", "-4", "route", "del", "table", PROTON_TABLE, "blackhole", prefix, "metric", BLACKHOLE_METRIC],
                protected=True, paths=paths, runner=runner)
        _action(state, ["ip", "-4", "route", "add", "table", PROTON_TABLE, prefix, "via", NS_IP, "dev", HOST_IF, "metric", "0"],
                ["ip", "-4", "route", "del", "table", PROTON_TABLE, prefix, "via", NS_IP, "dev", HOST_IF, "metric", "0"],
                paths=paths, runner=runner)
        _action(state, ["ip", "-4", "rule", "add", "priority", RULE_ENDPOINT, "to", prefix, "lookup", PROTON_TABLE],
                ["ip", "-4", "rule", "del", "priority", RULE_ENDPOINT, "to", prefix, "lookup", PROTON_TABLE],
                protected=True, paths=paths, runner=runner)
        _action(state, ["ip", "-4", "route", "add", prefix, "via", NS_IP, "dev", HOST_IF, "metric", "0", "proto", MANAGED_ROUTE_PROTO],
                ["ip", "-4", "route", "del", prefix, "via", NS_IP, "dev", HOST_IF, "metric", "0", "proto", MANAGED_ROUTE_PROTO],
                paths=paths, runner=runner)
    _action(state, ["ip", "-6", "route", "add", "blackhole", "default", "table", IPV6_TABLE],
            ["ip", "-6", "route", "del", "blackhole", "default", "table", IPV6_TABLE],
            protected=True, paths=paths, runner=runner)
    _action(state, ["ip", "-6", "rule", "add", "priority", RULE_IPV6, "lookup", IPV6_TABLE],
            ["ip", "-6", "rule", "del", "priority", RULE_IPV6, "lookup", IPV6_TABLE],
            protected=True, paths=paths, runner=runner)
    own_default = ["default", "via", NS_IP, "dev", HOST_IF, "metric", GATEWAY_METRIC, "proto", MANAGED_ROUTE_PROTO]
    _action(state, ["ip", "-4", "route", "add", *own_default], ["ip", "-4", "route", "del", *own_default], paths=paths, runner=runner)
    for route in inventory["defaults"]:
        journal_action(state, route, kind="restore_route", paths=paths)
        runner.run(["ip", "-4", "route", "del", *_route_args(route)])
    journal_action(state, ["resolvectl", "revert", HOST_IF], paths=paths)
    for command in (["resolvectl", "dns", HOST_IF, settings["dns"]],
                    ["resolvectl", "domain", HOST_IF, "~."],
                    ["resolvectl", "default-route", HOST_IF, "yes"]):
        runner.run(command)


def _receive_exact(sock, length):
    chunks = []
    while length:
        data = sock.recv(length)
        if not data:
            raise OuterError("The TCP connectivity probe returned an incomplete response.")
        chunks.append(data)
        length -= len(data)
    return b"".join(chunks)


def _dns_response_valid(response, query_id):
    if len(response) < 12:
        return False
    ident, flags = struct.unpack("!HH", response[:4])
    return ident == query_id and bool(flags & 0x8000) and (flags & 0x000f) == 0


def probe_tunnel(dns):
    dns = validate_dns(dns)
    query_id = int.from_bytes(os.urandom(2), "big")
    query = (struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
             + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(8)
            sock.connect((dns, 53))
            sock.sendall(query)
            if not _dns_response_valid(sock.recv(4096), query_id):
                raise OuterError("The UDP connectivity probe failed.")
        with socket.create_connection((dns, 53), timeout=8) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            size = struct.unpack("!H", _receive_exact(sock, 2))[0]
            if size > 4096 or not _dns_response_valid(_receive_exact(sock, size), query_id):
                raise OuterError("The TCP connectivity probe failed.")
    except (OSError, ValueError, struct.error) as exc:
        raise OuterError("The TCP or UDP connectivity probe failed.") from exc


def socks_ready():
    try:
        with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=1):
            return True
    except OSError:
        return False


def notify_systemd(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        raise OuterError("The supervisor must be launched by its systemd service.")
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode("utf-8"))
    except OSError as exc:
        raise OuterError("Could not notify systemd of gateway readiness.") from exc


class CoreProcess:
    def __init__(self, process, command):
        self.process = process
        self.command = command
        self.stderr_tail = bytearray()
        self.stderr_truncated = False
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader.start()

    def _read_stderr(self):
        try:
            while True:
                chunk = self.process.stderr.read(4096)
                if not isinstance(chunk, bytes) or not chunk:
                    return
                with self.lock:
                    self.stderr_tail.extend(chunk)
                    if len(self.stderr_tail) > 8192:
                        del self.stderr_tail[:-8192]
                        self.stderr_truncated = True
        except (OSError, ValueError):
            return

    def poll(self):
        return self.process.poll()

    def terminate(self):
        return self.process.terminate()

    def kill(self):
        return self.process.kill()

    def wait(self, timeout=None):
        result = self.process.wait(timeout=timeout)
        self.reader.join(timeout=1)
        return result

    def failure(self, label, runner=RUNNER):
        self.reader.join(timeout=1)
        with self.lock:
            stderr = bytes(self.stderr_tail)
            if self.stderr_truncated:
                _, separator, remainder = stderr.partition(b"\n")
                stderr = b"[earlier stderr omitted]\n" + (remainder if separator else b"")
            stderr = stderr.decode("utf-8", errors="replace")
        return command_failure(self.command, self.poll(), stderr, secrets=getattr(runner, "secrets", ()), label=label)


def _spawn_core(args):
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    try:
        command = command_argv(args)
    except OuterError as exc:
        raise command_failure(attempted_argv(args), None, str(exc), secrets=RUNNER.secrets,
                              label="Could not resolve command") from exc
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        return CoreProcess(process, command)
    except OSError as exc:
        raise command_failure(command, None, exc.strerror or type(exc).__name__,
                              secrets=RUNNER.secrets, label="Could not start command") from exc


def _stop_cores(children):
    for child in children:
        if child.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                child.terminate()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                child.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=5)


def _proton_peers(settings, runner=RUNNER):
    interface = settings["interface"]
    link = runner.run(["ip", "-d", "-j", "link", "show", "dev", interface], check=False)
    if link.returncode:
        return ()
    try:
        links = json.loads(link.stdout)
        info = links[0]
        if info.get("linkinfo", {}).get("info_kind") != "wireguard" or "UP" not in info.get("flags", []):
            return ()
    except (ValueError, IndexError, TypeError):
        return ()
    result = runner.run(["wg", "show", interface, "endpoints"], check=False)
    if result.returncode:
        return ()
    peers = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[1] == "(none)":
            return ()
        try:
            host, port_text = fields[1].rsplit(":", 1)
            host = str(ipaddress.IPv4Address(host))
            port = int(port_text)
        except (ValueError, IndexError):
            return ()
        if host not in settings["endpoints"] or not 1 <= port <= 65535:
            return ()
        peers.append((host, port))
    if not peers:
        return ()
    mark_result = runner.run(["wg", "show", interface, "fwmark"], check=False)
    if mark_result.returncode:
        return ()
    mark = mark_result.stdout.strip()
    if mark == "off":
        mark_args = []
    else:
        try:
            number = int(mark, 0)
            if not 0 <= number <= 0xffffffff:
                return ()
        except ValueError:
            return ()
        mark_args = ["mark", str(number)]
    for address, _ in peers:
        route = runner.run(["ip", "-j", "-4", "route", "get", address, *mark_args], check=False)
        try:
            if route.returncode or json.loads(route.stdout)[0].get("dev") != HOST_IF:
                return ()
        except (ValueError, IndexError, TypeError):
            return ()
    return tuple(sorted(set(peers)))


def _proton_handshake_recent(settings, runner=RUNNER):
    result = runner.run(["wg", "show", settings["interface"], "latest-handshakes"], check=False)
    if result.returncode:
        return False
    now = int(time.time())
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            return False
        try:
            handshake = int(fields[1])
        except ValueError:
            return False
        if handshake > 0 and now - 180 <= handshake <= now + 30:
            return True
    return False


def update_proton_guard(state, settings, previous, *, paths=PATHS, runner=RUNNER):
    peers = _proton_peers(settings, runner)
    handshake = bool(peers) and _proton_handshake_recent(settings, runner)
    latched = bool(state.get("proton_latched")) or handshake
    if peers == previous and latched == bool(state.get("proton_latched")):
        return previous
    script = _proton_guard_script(settings, peers, latched)
    runner.run(["nft", "-f", "-"], input_text=script)
    if latched:
        runner.run(["resolvectl", "revert", HOST_IF])
    else:
        for command in (["resolvectl", "dns", HOST_IF, settings["dns"]],
                        ["resolvectl", "domain", HOST_IF, "~."],
                        ["resolvectl", "default-route", HOST_IF, "yes"]):
            runner.run(command)
    state["proton_ready"] = bool(peers)
    state["proton_latched"] = latched
    save_state(state, paths)
    if latched and peers:
        message = "Proton WireGuard handshake observed; outer-only traffic is blocked."
    elif latched or settings.get("strict", False):
        message = "Waiting for Proton; outer-only traffic is blocked."
    else:
        message = "Waiting for Proton; IPv4 traffic uses the outer tunnel."
    print(message, flush=True)
    return peers


def dependencies_ok(runner=RUNNER):
    missing = [name for name, paths in SYSTEM_TOOLS.items()
               if not any(os.path.isfile(path) and os.access(path, os.X_OK) for path in paths)]
    if missing:
        raise OuterError("Missing required system tools: " + ", ".join(missing) + ".")
    if not Path("/dev/net/tun").exists():
        raise OuterError("The TUN device is unavailable; load the tun kernel module first.")
    command = ["systemctl", "is-active", "--quiet", "systemd-resolved.service"]
    result = runner.run(command, check=False)
    if result.returncode:
        raise command_failure(getattr(result, "args", command), result.returncode, result.stderr,
                              secrets=getattr(runner, "secrets", ()), label="systemd-resolved must be running")


def preflight(env_path, paths=PATHS, runner=RUNNER):
    settings = read_settings(env_path)
    register_settings_secrets(settings, runner)
    server = checked_server(settings)
    dependencies_ok(runner)
    if installed_binary_integrity(paths):
        validate_configs(settings, server, paths, runner)
        print("Installed core binaries and generated configs passed validation.")
    else:
        print("The core binaries are not installed yet; install will offer verified downloads.")
    if legacy_paths(paths):
        print("A legacy outer gateway was detected; it will be backed up before migration.")
    print("Preflight passed. Proton must be disconnected before the gateway starts.")


def dry_run(env_path, paths=PATHS):
    settings = read_settings(env_path)
    print("Dry run only; no files, routes, firewall rules or services were changed.")
    print("Would validate VLESS TCP REALITY vision and both generated core configs.")
    print(f"Would allow {len(settings['endpoints'])} configured Proton IPv4 endpoint(s) via {settings['interface']}.")
    print("Would set up a namespace, veth, NAT, sing-box TUN, Xray SOCKS bridge and one systemd service.")
    print("Would probe TCP and UDP before changing the default route and block IPv6 and direct IPv4 traffic.")
    print("Before Proton: " + ("block outer-only traffic." if settings["strict"] else "allow IPv4 through the outer tunnel."))
    print(f"Detected {len(legacy_paths(paths))} legacy path(s); migration creates a protected backup.")


def _make_state(settings, server, env_bytes, paths=PATHS):
    state = {"version": 1, "phase": "transition", "server": server,
             "env_sha256": hashlib.sha256(env_bytes).hexdigest(),
             "proton_ready": False, "proton_latched": False,
             "strict_mode": settings.get("strict", False), "undo": []}
    save_state(state, paths)
    return state


def supervise(paths=PATHS, runner=RUNNER):
    require_root()
    settings, env_bytes = read_settings_and_data(paths.env)
    register_settings_secrets(settings, runner)
    state = load_state(paths)
    if state:
        if state.get("phase") != "transition" or state.get("env_sha256") != hashlib.sha256(env_bytes).hexdigest():
            raise OuterError("The recovery journal does not match this configuration; run stop first.")
        server = state["server"]
    else:
        if legacy_paths(paths) or systemd_active(runner, LEGACY_UNIT):
            raise OuterError("Use outer.py start to migrate the legacy gateway safely.")
        dependencies_ok(runner)
        server = checked_server(settings)
        validate_configs(settings, server, paths, runner)
        physical = prepare_nft_rules(settings, server, runner)
        state = _make_state(settings, server, env_bytes, paths)
        state["validated_physical"] = physical
        save_state(state, paths)
        add_transition(state, paths, runner)
    children = []
    stopping = False
    ready = False
    failed = False

    def on_signal(signum, frame):
        nonlocal stopping
        stopping = True

    old_term = signal.signal(signal.SIGTERM, on_signal)
    old_int = signal.signal(signal.SIGINT, on_signal)
    try:
        inventory = network_inventory(server, settings["endpoints"], settings["interface"], runner)
        if state.get("validated_physical") and inventory["physical"] != state["validated_physical"]:
            raise OuterError("The outer-server interface changed after nft validation; run stop and retry.")
        _network_before_cores(state, settings, server, inventory, paths, runner)
        children.append(_spawn_core(["ip", "netns", "exec", NAMESPACE, paths.xray, "run", "-config", paths.runtime / "xray.json"]))
        children.append(_spawn_core(["ip", "netns", "exec", NAMESPACE, paths.sing, "run", "-c", paths.runtime / "sing-box.json"]))
        for _ in range(80):
            if stopping:
                break
            for child in children:
                if child.poll() is not None:
                    raise child.failure("A tunnel core stopped before it was ready", runner)
            tun = runner.run(["ip", "-n", NAMESPACE, "link", "show", "dev", TUN_IF], check=False)
            socks = runner.run(["ip", "netns", "exec", NAMESPACE, sys.executable, paths.script, "_socks-ready"], check=False, timeout=3)
            if tun.returncode == 0 and socks.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise OuterError("The tunnel cores did not become ready.")
        if not stopping:
            runner.run(["ip", "netns", "exec", NAMESPACE, sys.executable, paths.script, "_probe", settings["dns"]], timeout=25)
            _network_after_probe(state, settings, inventory, paths, runner)
            state["phase"] = "running"
            save_state(state, paths)
            previous = update_proton_guard(state, settings, (), paths=paths, runner=runner)
            drop_transition(state, paths, runner)
            notify_systemd("READY=1\nSTATUS=Outer gateway ready; waiting for verified Proton WireGuard")
            ready = True
            while not stopping:
                for child in children:
                    if child.poll() is not None:
                        raise child.failure("A tunnel core stopped unexpectedly; traffic remains blocked", runner)
                previous = update_proton_guard(state, settings, previous, paths=paths, runner=runner)
                time.sleep(1)
    except (OuterError, OSError, ValueError) as exc:
        failed = True
        message = journal_failure(state, str(exc), paths=paths, runner=runner)
        print(f"Gateway error: {message}", file=sys.stderr, flush=True)
    finally:
        _stop_cores(children)
        try:
            cleanup(state, preserve_guard=not stopping, paths=paths, runner=runner)
        except (OuterError, OSError) as exc:
            failed = True
            print(f"Gateway cleanup error: {exc}", file=sys.stderr, flush=True)
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)
    if stopping and not failed:
        return 0
    return 1 if failed or not ready else 0


def _restore_migration(tx, was_active, was_enabled, paths=PATHS, runner=RUNNER):
    tx.rollback()
    restore_legacy_service(was_active, was_enabled, runner)


def _pending_migration(state, paths=PATHS):
    if not state or not state.get("migration_backup"):
        return None
    directory = Path(state["migration_backup"])
    if directory.is_symlink() or directory.resolve().parent != paths.backups.resolve():
        raise OuterError("The legacy migration backup path is invalid; the guard remains active.")
    if (directory / "migration-complete").is_file():
        return None
    tx = FileTransaction.reopen(paths, directory)
    try:
        legacy = json.loads((directory / "legacy-systemd.json").read_text(encoding="utf-8"))
        if not isinstance(legacy.get("active"), bool) or not isinstance(legacy.get("enabled"), str):
            raise ValueError
    except (OSError, ValueError, TypeError) as exc:
        raise OuterError("The legacy migration service state is unavailable; the guard remains active.") from exc
    return tx, legacy


def _finish_migration(tx, outcome):
    atomic_write(tx.directory / "migration-complete", (outcome + "\n").encode(), 0o600)


def start(paths=PATHS, runner=RUNNER):
    require_root()
    if systemd_active(runner):
        print("Gateway service is already running.")
        return
    if load_state(paths):
        raise OuterError("A previous gateway run left a recovery guard; run stop before starting again.")
    dependencies_ok(runner)
    settings, env_bytes = read_settings_and_data(paths.env)
    register_settings_secrets(settings, runner)
    server = checked_server(settings)
    validate_configs(settings, server, paths, runner)
    physical = prepare_nft_rules(settings, server, runner)
    legacy = legacy_paths(paths)
    was_active = systemd_active(runner, LEGACY_UNIT)
    was_enabled = systemd_enabled(runner, LEGACY_UNIT) if legacy or was_active else ""
    tx = None
    state = _make_state(settings, server, env_bytes, paths)
    state["validated_physical"] = physical
    save_state(state, paths)
    try:
        add_transition(state, paths, runner)
        if legacy or was_active:
            tx = FileTransaction(paths, "legacy-migration")
            for path in legacy:
                tx.snapshot(path)
            atomic_json(tx.directory / "legacy-systemd.json", {"active": was_active, "enabled": was_enabled})
            state["migration_backup"] = str(tx.directory)
            save_state(state, paths)
            if was_active:
                runner.run(["systemctl", "stop", LEGACY_UNIT], timeout=60)
            if was_enabled in ("enabled", "enabled-runtime"):
                runner.run(["systemctl", "disable", LEGACY_UNIT])
            for path in legacy:
                tx.remove(path)
            runner.run(["systemctl", "daemon-reload"])
        runner.run(["systemctl", "start", UNIT_NAME], timeout=130)
        if tx:
            _finish_migration(tx, "committed")
    except BaseException as exc:
        failure_state = load_state(paths) or state
        cause = failure_state.get("last_error") or redact_text(exc, getattr(runner, "secrets", ()))
        service_error = redact_text(exc, getattr(runner, "secrets", ()))
        if service_error and service_error != cause:
            cause += "\nService manager: " + service_error
        journal_failure(failure_state, cause, paths=paths, runner=runner)
        atomic_write(paths.runtime / "hold-guard", b"hold\n", 0o600)
        with contextlib.suppress(OuterError):
            runner.run(["systemctl", "stop", UNIT_NAME], check=False, timeout=60)
        try:
            cleanup(preserve_guard=True, paths=paths, runner=runner)
        except OuterError:
            pass
        restored = False
        if tx is not None:
            try:
                _restore_migration(tx, was_active, was_enabled, paths, runner)
                _finish_migration(tx, "rolled back")
                restored = True
            except (OuterError, OSError):
                restored = False
        if restored and was_active:
            try:
                (paths.runtime / "hold-guard").unlink(missing_ok=True)
                cleanup(preserve_guard=False, paths=paths, runner=runner)
            except (OuterError, OSError):
                restored = False
        if restored and was_active:
            raise OuterError("Start failed; the previous legacy gateway was restored.\n" + cause) from exc
        raise OuterError("Start failed; run stop to clean up gateway changes.\n" + cause) from exc
    if tx:
        print(f"Legacy gateway migrated. Backup: {tx.directory}")
    print("Outer gateway started. Connect Proton WireGuard using an allowlisted endpoint.")


def stop(paths=PATHS, runner=RUNNER):
    require_root()
    state = load_state(paths)
    if not lexists(paths.unit) and not state:
        guards = _active_guards(runner)
        if guards:
            raise OuterError("A gateway guard exists without a recovery journal; it was not removed: " +
                             ", ".join(guards) + ".")
        print("Gateway is already stopped.")
        return
    pending = _pending_migration(state, paths)
    if pending and state.get("phase") == "running" and systemd_active(runner):
        _finish_migration(pending[0], "committed")
        pending = None
    if pending:
        atomic_write(paths.runtime / "hold-guard", b"hold\n", 0o600)
    result = runner.run(["systemctl", "stop", UNIT_NAME], check=False, timeout=60)
    if result.returncode:
        inactive = runner.run(["systemctl", "is-active", "--quiet", UNIT_NAME], check=False)
        if inactive.returncode not in (3, 4):
            args = getattr(result, "args", ["systemctl", "stop", UNIT_NAME])
            detail = command_failure(args, result.returncode, result.stderr,
                                     secrets=getattr(runner, "secrets", ()), label="Could not stop service")
            raise OuterError(f"The traffic guard was not removed.\n{detail}")
    if pending:
        try:
            cleanup(preserve_guard=True, paths=paths, runner=runner)
        except (OuterError, OSError):
            pass
        tx, legacy = pending
        try:
            _restore_migration(tx, legacy["active"], legacy["enabled"], paths, runner)
            _finish_migration(tx, "rolled back")
        except (OuterError, OSError) as exc:
            migration_error = redact_text(exc, getattr(runner, "secrets", ()))
        else:
            migration_error = None
            print(f"Interrupted legacy migration restored. Backup: {tx.directory}")
    else:
        migration_error = None
    (paths.runtime / "hold-guard").unlink(missing_ok=True)
    try:
        cleanup(preserve_journal=bool(migration_error), paths=paths, runner=runner)
    except (OuterError, OSError) as exc:
        if migration_error:
            raise OuterError(f"Legacy migration recovery failed: {migration_error}\n{exc}") from exc
        raise
    if migration_error:
        state = load_state(paths)
        if state:
            journal_failure(state, migration_error, paths=paths, runner=runner)
        raise OuterError(f"Legacy migration recovery failed; retry stop.\n{migration_error}")
    guards = _active_guards(runner)
    if guards:
        raise OuterError("A gateway guard remains without a matching cleanup action; it was not removed: " +
                         ", ".join(guards) + ".")
    print("Gateway stopped; its traffic guard was removed.")


def status(paths=PATHS, runner=RUNNER):
    try:
        active = systemd_active(runner)
    except OuterError as exc:
        active = False
        print(f"Gateway service: unknown ({exc})")
    else:
        print("Gateway service: " + ("active" if active else "inactive"))
    state = None
    try:
        state = load_state(paths)
    except PermissionError:
        print("Recovery journal: inaccessible; run status with sudo.")
    except OuterError as exc:
        print(f"Recovery journal: invalid ({exc})")
    else:
        print("Recovery journal: " + ("present" if state else "not present"))
    try:
        guards = _active_guards(runner)
    except OuterError as exc:
        print(f"Gateway traffic guard: unknown ({exc})")
    else:
        print("Gateway traffic guard: " + ("present (" + ", ".join(guards) + ")" if guards else "not present"))
        if guards and not state:
            print("Warning: the guard has no readable recovery journal; no unowned tables will be removed.")
    if state:
        print("Gateway state: " + str(state.get("phase", "unknown")))
        if state.get("last_error"):
            print("Last gateway error: " + redact_text(state["last_error"], getattr(runner, "secrets", ())))
        verified = active and state.get("phase") == "running" and state.get("proton_ready")
        print("Proton WireGuard: " + ("verified" if verified else "not verified"))
        if active and state.get("phase") == "running":
            mode = "Proton only" if state.get("proton_latched") or state.get("strict_mode") else "outer bootstrap"
            print("Traffic mode: " + mode)


def uninstall(paths=PATHS, runner=RUNNER):
    require_root()
    targets = [paths.unit, paths.script, paths.sing, paths.xray, paths.manifest, paths.env]
    if not any(lexists(path) for path in targets) and not load_state(paths):
        print("Gateway is already uninstalled.")
        return
    if paths.unit.is_file() and MANAGED_MARKER not in paths.unit.read_text(encoding="utf-8", errors="replace"):
        raise OuterError("The service file is not managed by outer.py; it was not removed.")
    active = systemd_active(runner)
    enabled = systemd_enabled(runner) if lexists(paths.unit) else ""
    tx = FileTransaction(paths, "uninstall")
    for path in targets:
        tx.snapshot(path)
    try:
        stop(paths, runner)
        if enabled in ("enabled", "enabled-runtime"):
            runner.run(["systemctl", "disable", UNIT_NAME])
        for path in targets:
            tx.remove(path)
        runner.run(["systemctl", "daemon-reload"])
    except BaseException:
        tx.rollback()
        with contextlib.suppress(OuterError):
            runner.run(["systemctl", "daemon-reload"])
            if enabled in ("enabled", "enabled-runtime"):
                command = ["systemctl", "enable"] + (["--runtime"] if enabled == "enabled-runtime" else [])
                runner.run(command + [UNIT_NAME])
            if active:
                start(paths, runner)
        raise
    for directory in (paths.prefix, paths.env.parent):
        with contextlib.suppress(OSError):
            directory.rmdir()
    print(f"Uninstalled. Recovery backups remain in {paths.backups}.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Manage a fail-closed outer VLESS gateway.")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "dry-run", "debug-rules", "apply"):
        child = sub.add_parser(command)
        child.add_argument("--env", default=".env", help="data-only configuration file (default: .env)")
    install_parser = sub.add_parser("install")
    install_parser.add_argument("--yes", action="store_true", help="confirm official release downloads")
    install_parser.add_argument("--env", default=".env", help="data-only configuration file (default: .env)")
    for command in ("start", "stop", "status", "uninstall", "_supervise", "_post-stop", "_socks-ready", "_nft-kernel-probe"):
        sub.add_parser(command, help=argparse.SUPPRESS if command.startswith("_") else None)
    probe = sub.add_parser("_probe", help=argparse.SUPPRESS)
    probe.add_argument("dns")
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            preflight(args.env)
        elif args.command == "dry-run":
            dry_run(args.env)
        elif args.command == "debug-rules":
            debug_rules(args.env)
        elif args.command == "_probe":
            probe_tunnel(args.dns)
        elif args.command == "_socks-ready":
            return 0 if socks_ready() else 1
        elif args.command == "_nft-kernel-probe":
            require_root()
            run_nft_kernel_probe(json.load(sys.stdin))
        elif args.command == "_supervise":
            return supervise()
        elif args.command == "_post-stop":
            require_root()
            cleanup(preserve_guard=os.environ.get("SERVICE_RESULT") != "success")
        elif args.command == "status":
            status()
        else:
            require_root()
            with operation_lock():
                if args.command == "install":
                    install(confirmed=args.yes, env_path=args.env)
                elif args.command == "apply":
                    apply_config(args.env)
                elif args.command == "start":
                    start()
                elif args.command == "stop":
                    stop()
                elif args.command == "uninstall":
                    uninstall()
        return 0
    except (OuterError, ValueError, OSError, json.JSONDecodeError) as exc:
        message = redact_text(exc, RUNNER.secrets)
        print(f"Error: {message}", file=sys.stderr)
        log_failure(message)
        return 1


if __name__ == "__main__":
    sys.exit(main())
