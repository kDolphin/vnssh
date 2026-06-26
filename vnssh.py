#!/usr/bin/env python3
"""vnssh - macOS SSH launcher with search, favorites, and Keychain passwords."""

from __future__ import annotations

import csv
import curses
import base64
import fcntl
import gzip
import json
import os
import pty
import re
import secrets
import select
import shlex
import shutil
import signal
import subprocess
import sys
import termios
import time
import tty
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

VNSSH_DIR = Path.home() / ".vnssh"
VNSSH_TERMINAL_TITLE = "vnssh"
SESSIONS_DIR = VNSSH_DIR / "sessions"
HOSTS_CONF = VNSSH_DIR / "hosts.conf"
HISTORY_FILE = VNSSH_DIR / "history.json"
SSH_CONFIG = Path.home() / ".ssh" / "config"
KEYCHAIN_SERVICE = "vnssh"
INCLUDE_MARKER = "Include ~/.vnssh/hosts.conf"
FOLDER_COMMENT_PREFIX = "#v-f:"
LEGACY_COMMENT_PREFIX = "#v-legacy"
TWOFA_COMMENT_PREFIX = "#v-2fa"
_DEPRECATED_TWOFA_COMMENT_PREFIX = "#v-bastion"
SSH_CONNECT_OPTIONS = (
    ("StrictHostKeyChecking", "accept-new"),
    ("ConnectTimeout", "5"),
)
PROBE_CONNECT_TIMEOUT = 2
AUTO_LEGACY_FAST_PROBE_MAX = 5.0
AUTO_LEGACY_SLOW_DEFAULT_MIN = 5.0
LEGACY_SSH_OPTIONS = (
    (
        "KexAlgorithms",
        # Prefer fast fixed-group KEX first; "+" would append after OpenSSH
        # defaults and still negotiate slow diffie-hellman-group-exchange-sha256.
        "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,"
        "diffie-hellman-group1-sha1",
    ),
    ("HostKeyAlgorithms", "+ssh-rsa"),
    ("PubkeyAcceptedAlgorithms", "+ssh-rsa"),
    (
        "Ciphers",
        "+aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
    ),
    ("MACs", "+hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-md5,hmac-md5-96"),
)
FOLDER_UNCATEGORIZED = "Uncategorized"
FOLDER_UNCATEGORIZED_ALIASES = frozenset({FOLDER_UNCATEGORIZED})
COL_FOLDER_MIN = 12
COL_FOLDER_MAX = 24
COL_HOST_MIN = 16
COL_HOST_MAX = 32
COL_ADDR_MIN = 12
COL_ADDR_MAX = 48
COL_FLAGS_W = 9
COL_PREFIX_W = 2
TABLE_MAX_WIDTH = 120
TABLE_GAPS = 3
SEARCH_PREFIX = "> "
SEARCH_CURSOR_BLINK_MS = 500
DEFAULT_PORT = 22
DEFAULT_IDENTITY = "~/.ssh/id_ed25519"
MIN_TERMINAL_HEIGHT = 16
MIN_PAGE_SIZE = 3
KEY_CTRL_N = 14
HELP_HINTS: List[Tuple[str, str]] = [
    ("Enter", "connect"),
    ("C-n", "new"),
    ("e", "edit"),
    ("d", "delete"),
    ("↑↓", "select"),
    ("PgUp/PgDn C-b/C-f", "page"),
    ("Esc", "clear/quit"),
]
HELP_SPLIT_INDEX = 4
HELP_SEGMENT_SEP = "  "

AUTH_PASSWORD = "password"
AUTH_KEY = "key"
AUTH_BOTH = "both"

AUTH_LABELS = {
    AUTH_PASSWORD: "Password",
    AUTH_KEY: "SSH key",
    AUTH_BOTH: "Password + key",
}

IMPORT_TEMPLATE_FILENAME = "vnssh-hosts-template.csv"

IMPORT_COLUMNS = {
    "category": ("category", "folder", "group"),
    "host": ("host", "name", "alias", "session_name"),
    "hostname": ("hostname", "host_name", "ip", "address", "addr"),
    "user": ("user", "username", "account"),
    "port": ("port",),
    "password": ("password", "pass", "pwd"),
    "identity_file": (
        "identity_file",
        "identityfile",
        "key",
        "keyfile",
        "private_key",
    ),
    "auth": ("auth", "authentication"),
}

IMPORT_TEMPLATE_FIELDNAMES = (
    "category",
    "host",
    "hostname",
    "user",
    "port",
    "password",
    "identity_file",
    "auth",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Connection:
    host: str
    hostname: str = ""
    user: str = ""
    port: int = DEFAULT_PORT
    identity_file: Optional[str] = None
    auth: str = AUTH_PASSWORD
    managed: bool = False
    has_password: bool = False
    folder: str = FOLDER_UNCATEGORIZED
    search_blob: str = ""

    @property
    def folder_display(self) -> str:
        return normalize_folder(self.folder)

    @property
    def label(self) -> str:
        addr = self.hostname or "?"
        user = self.user or "?"
        suffix = f":{self.port}" if self.port != DEFAULT_PORT else ""
        return f"{user}@{addr}{suffix}"

    @property
    def badges(self) -> str:
        flags = format_conn_flags(self)
        return "" if flags == "-" else flags


@dataclass
class ConnectResult:
    returncode: int
    stderr: str = ""
    stdout: str = ""


@dataclass
class WizardData:
    host: str = ""
    hostname: str = ""
    port: str = str(DEFAULT_PORT)
    user: str = ""
    auth: str = AUTH_PASSWORD
    identity_file: str = DEFAULT_IDENTITY
    password: str = ""
    folder: str = ""
    original_host: str = ""


# ---------------------------------------------------------------------------
# Keychain (macOS security CLI)
# ---------------------------------------------------------------------------


def keychain_get(account: str) -> Optional[str]:
    proc = subprocess.run(
        [
            "security",
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
            "-w",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.rstrip("\n")


def keychain_set(account: str, password: str) -> None:
    keychain_delete(account, invalidate=False)
    proc = subprocess.run(
        [
            "security",
            "add-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
            "-w",
            password,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Failed to write Keychain")
    invalidate_keychain_cache()


def keychain_delete(account: str, invalidate: bool = True) -> None:
    subprocess.run(
        [
            "security",
            "delete-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
        ],
        capture_output=True,
        text=True,
    )
    if invalidate:
        invalidate_keychain_cache()


_KEYCHAIN_ACCOUNTS_CACHE: Optional[set[str]] = None


def invalidate_keychain_cache() -> None:
    global _KEYCHAIN_ACCOUNTS_CACHE
    _KEYCHAIN_ACCOUNTS_CACHE = None


def parse_keychain_acct(block: str) -> Optional[str]:
    """Parse account name from a single dump-keychain genp attributes block."""
    match = re.search(r'"acct"<blob>="([^"]+)"', block)
    if match:
        return match.group(1)

    match = re.search(r'"acct"<blob>=0x([0-9A-Fa-f]+)', block)
    if match:
        try:
            return bytes.fromhex(match.group(1)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return None


def _vnssh_genp_section(entry: str) -> Optional[str]:
    """Return the attributes block for one vnssh generic-password item."""
    if 'class: "genp"' not in entry:
        return None
    genp = entry.split('class: "genp"', 1)[1]
    genp = re.split(r'\nclass: "', genp, maxsplit=1)[0]
    if not re.search(
        rf'(?:"svce"<blob>="{re.escape(KEYCHAIN_SERVICE)}"'
        rf'|0x00000007 <blob>="{re.escape(KEYCHAIN_SERVICE)}")',
        genp,
    ):
        return None
    return genp


def load_keychain_accounts() -> set[str]:
    """Load all vnssh Keychain account names in one dump (fast)."""
    global _KEYCHAIN_ACCOUNTS_CACHE
    if _KEYCHAIN_ACCOUNTS_CACHE is not None:
        return _KEYCHAIN_ACCOUNTS_CACHE

    accounts: set[str] = set()
    keychain_path = Path.home() / "Library/Keychains/login.keychain-db"
    if keychain_path.exists():
        proc = subprocess.run(
            ["security", "dump-keychain", str(keychain_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0:
            # Split per keychain item. Splitting only on class:"genp" merges many
            # unrelated entries and breaks non-ASCII account names stored as hex.
            for entry in re.split(r"\nkeychain:", proc.stdout):
                genp = _vnssh_genp_section(entry)
                if genp is None:
                    continue
                account = parse_keychain_acct(genp)
                if account:
                    accounts.add(account)

    _KEYCHAIN_ACCOUNTS_CACHE = accounts
    return accounts


def keychain_has(account: str) -> bool:
    return account in load_keychain_accounts()


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


def load_history() -> Dict[str, dict]:
    if not HISTORY_FILE.exists():
        return {}
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_history(data: Dict[str, dict]) -> None:
    VNSSH_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def record_use(host: str) -> None:
    data = load_history()
    entry = data.get(host, {"count": 0, "last_used": ""})
    entry["count"] = int(entry.get("count", 0)) + 1
    entry["last_used"] = datetime.now(timezone.utc).isoformat()
    data[host] = entry
    save_history(data)


def history_score(host: str) -> float:
    data = load_history()
    entry = data.get(host)
    if not entry:
        return 0.0
    count = float(entry.get("count", 0))
    last_used = entry.get("last_used", "")
    recency = 0.0
    if last_used:
        try:
            dt = datetime.fromisoformat(last_used)
            age_days = (datetime.now(timezone.utc) - dt).total_seconds() / 86400
            recency = max(0.0, 1.0 - age_days / 30.0)
        except ValueError:
            recency = 0.0
    return count * 0.7 + recency * 0.3


def rename_history(old: str, new: str) -> None:
    if old == new:
        return
    data = load_history()
    if old in data:
        data[new] = data.pop(old)
        save_history(data)


def delete_history(host: str) -> None:
    data = load_history()
    if host in data:
        del data[host]
        save_history(data)


# ---------------------------------------------------------------------------
# SSH config parsing & writing
# ---------------------------------------------------------------------------


def expand_path(path: str) -> Path:
    return Path(os.path.expanduser(path.strip()))


def read_config_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def parse_folder_comment(line: str) -> Optional[str]:
    stripped = line.strip()
    if stripped.startswith(FOLDER_COMMENT_PREFIX):
        return stripped[len(FOLDER_COMMENT_PREFIX) :].strip()
    return None


def parse_legacy_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped == LEGACY_COMMENT_PREFIX or stripped.startswith(
        f"{LEGACY_COMMENT_PREFIX}:"
    )


def parse_twofa_comment(line: str) -> bool:
    stripped = line.strip()
    if stripped == _DEPRECATED_TWOFA_COMMENT_PREFIX or stripped.startswith(
        f"{_DEPRECATED_TWOFA_COMMENT_PREFIX}:"
    ):
        return True
    return stripped == TWOFA_COMMENT_PREFIX or stripped.startswith(
        f"{TWOFA_COMMENT_PREFIX}:"
    )


def is_uncategorized_folder(folder: str) -> bool:
    value = folder.strip()
    return not value or value in FOLDER_UNCATEGORIZED_ALIASES


def normalize_folder(folder: str) -> str:
    value = folder.strip()
    if is_uncategorized_folder(value):
        return FOLDER_UNCATEGORIZED
    return value


def parse_config_entries(text: str) -> List[Tuple[str, Dict[str, str], str]]:
    """Return list of (host_pattern, options dict, folder) in file order."""
    entries: List[Tuple[str, Dict[str, str], str]] = []
    current_hosts: List[str] = []
    current_opts: Dict[str, str] = {}
    current_folder = FOLDER_UNCATEGORIZED
    current_legacy = False
    current_twofa = False
    in_match = False

    def flush_hosts() -> None:
        nonlocal current_hosts, current_opts, current_legacy, current_twofa
        for h in current_hosts:
            opts = dict(current_opts)
            if current_legacy:
                opts["_vnssh_legacy"] = "1"
            if current_twofa:
                opts["_vnssh_2fa"] = "1"
            entries.append((h, opts, current_folder))
        current_hosts = []
        current_opts = {}
        current_legacy = False
        current_twofa = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            folder = parse_folder_comment(line)
            if folder is not None:
                if current_hosts and not in_match:
                    flush_hosts()
                current_folder = normalize_folder(folder)
                continue
            if parse_legacy_comment(line):
                current_legacy = True
            if parse_twofa_comment(line):
                current_twofa = True
            continue
        lower = line.lower()
        if lower.startswith("match "):
            if current_hosts and not in_match:
                flush_hosts()
            current_hosts = []
            current_opts = {}
            in_match = True
            continue
        if in_match:
            continue
        if lower.startswith("host "):
            if current_hosts:
                flush_hosts()
            parts = shlex.split(line)
            current_hosts = parts[1:] if len(parts) > 1 else []
            current_opts = {}
            continue
        if " " in line or "\t" in line:
            key, _, value = line.partition(" ")
            key = key.strip().lower()
            value = value.strip()
            if key and value:
                current_opts[key] = value

    if current_hosts and not in_match:
        flush_hosts()

    return entries


def collect_includes(text: str, base_dir: Path) -> List[Path]:
    paths: List[Path] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("include "):
            pattern = line.split(None, 1)[1].strip()
            expanded = expand_path(pattern)
            if "*" in pattern or "?" in pattern:
                parent = expanded.parent
                glob_part = expanded.name
                if parent.exists():
                    for match in sorted(parent.glob(glob_part)):
                        if match.is_file():
                            paths.append(match)
            elif expanded.exists() and expanded.is_file():
                paths.append(expanded)
            elif expanded.parent.exists():
                # OpenSSH may include missing files silently; skip.
                pass
    return paths


def is_listable_host(name: str) -> bool:
    if not name or name == "*":
        return False
    if "*" in name or "?" in name:
        return False
    return True


_RAW_HOSTS_CACHE: Optional[Tuple[float, float, Dict[str, Tuple[Dict[str, str], Path, str]]]] = (
    None
)


def _config_cache_times() -> Tuple[float, float]:
    hosts_mtime = HOSTS_CONF.stat().st_mtime if HOSTS_CONF.exists() else 0.0
    ssh_mtime = SSH_CONFIG.stat().st_mtime if SSH_CONFIG.exists() else 0.0
    return hosts_mtime, ssh_mtime


def gather_raw_hosts() -> Dict[str, Tuple[Dict[str, str], Path, str]]:
    """Map host alias -> (options, source file, folder)."""
    global _RAW_HOSTS_CACHE
    hosts_mtime, ssh_mtime = _config_cache_times()
    if (
        _RAW_HOSTS_CACHE is not None
        and _RAW_HOSTS_CACHE[0] == hosts_mtime
        and _RAW_HOSTS_CACHE[1] == ssh_mtime
    ):
        return _RAW_HOSTS_CACHE[2]

    seen: Dict[str, Tuple[Dict[str, str], Path, str]] = {}
    visited: set[Path] = set()

    def walk(path: Path) -> None:
        path = path.resolve()
        if path in visited:
            return
        visited.add(path)
        text = read_config_text(path)
        for host_name, opts, folder in parse_config_entries(text):
            if is_listable_host(host_name) and host_name not in seen:
                seen[host_name] = (opts, path, folder)
        for include_path in collect_includes(text, path.parent):
            walk(include_path)

    if SSH_CONFIG.exists():
        walk(SSH_CONFIG)
    if HOSTS_CONF.exists():
        walk(HOSTS_CONF)
    _RAW_HOSTS_CACHE = (hosts_mtime, ssh_mtime, seen)
    return seen


def resolve_with_ssh_g(host: str) -> Dict[str, str]:
    proc = subprocess.run(
        ["ssh", "-G", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    result: Dict[str, str] = {}
    if proc.returncode != 0:
        return result
    for line in proc.stdout.splitlines():
        if " " not in line:
            continue
        key, value = line.split(" ", 1)
        result[key] = value
    return result


def resolve_connection_fields(host: str, opts: Dict[str, str]) -> Tuple[str, str, int]:
    """Prefer parsed config; ssh -G only when HostName is missing."""
    hostname = opts.get("hostname", "")
    user = opts.get("user", "")
    port_str = opts.get("port", str(DEFAULT_PORT))

    if not hostname:
        resolved = resolve_with_ssh_g(host)
        hostname = resolved.get("hostname") or hostname
        user = resolved.get("user") or user
        port_str = resolved.get("port") or port_str

    try:
        port = int(port_str)
    except ValueError:
        port = DEFAULT_PORT
    return hostname, user, port


def infer_auth(opts: Dict[str, str], has_password: bool) -> str:
    identity = opts.get("identityfile", "")
    if identity and has_password:
        return AUTH_BOTH
    if identity:
        return AUTH_KEY
    return AUTH_PASSWORD


_SSH_G_CACHE: Dict[str, Dict[str, str]] = {}
_SSH_G_IDENTITY_CACHE: Dict[str, List[str]] = {}

_DEFAULT_SSH_IDENTITY_NAMES = frozenset(
    {
        "id_rsa",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519",
        "id_ed25519_sk",
        "id_xmss",
        "id_dsa",
    }
)


def resolve_with_ssh_g_cached(host: str) -> Dict[str, str]:
    if host not in _SSH_G_CACHE:
        _SSH_G_CACHE[host] = resolve_with_ssh_g(host)
    return _SSH_G_CACHE[host]


def ssh_g_identity_files(host: str) -> List[str]:
    if host not in _SSH_G_IDENTITY_CACHE:
        proc = subprocess.run(
            ["ssh", "-G", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
        paths: List[str] = []
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.startswith("identityfile "):
                    paths.append(line.split(" ", 1)[1].strip())
        _SSH_G_IDENTITY_CACHE[host] = paths
    return _SSH_G_IDENTITY_CACHE[host]


def is_default_ssh_identity(path: str) -> bool:
    expanded = os.path.expanduser(path)
    return (
        os.path.basename(expanded) in _DEFAULT_SSH_IDENTITY_NAMES
        and os.path.dirname(expanded) == os.path.expanduser("~/.ssh")
    )


def configured_identity_file(host: str, opts: Dict[str, str]) -> str:
    """Return a user-configured IdentityFile, ignoring OpenSSH default key paths."""
    explicit = opts.get("identityfile", "")
    if explicit:
        return explicit
    for path in ssh_g_identity_files(host):
        if path and not is_default_ssh_identity(path):
            return path
    return ""


def connection_auth_mode(host: str) -> str:
    """Resolve auth mode for connect-time SSH args (may run ssh -G when needed)."""
    entry = gather_raw_hosts().get(host)
    opts = entry[0] if entry else {}
    explicit = opts.get("identityfile", "")
    has_pw = keychain_has(host)
    if explicit:
        return infer_auth({"identityfile": explicit}, has_pw)
    if not has_pw:
        return infer_auth({"identityfile": ""}, False)
    for path in ssh_g_identity_files(host):
        if path and not is_default_ssh_identity(path):
            return AUTH_BOTH
    return AUTH_PASSWORD


def password_delivery_mode(
    host: str, *, interactive: bool
) -> Tuple[bool, bool]:
    """Return (use_askpass, use_pty_password_inject) for Keychain-backed hosts."""
    if not keychain_has(host):
        return False, False
    if interactive and host_2fa_enabled(host):
        return False, True
    return True, False


def load_connections() -> List[Connection]:
    raw = gather_raw_hosts()
    connections: List[Connection] = []
    managed_path = HOSTS_CONF.resolve()
    keychain_accounts = load_keychain_accounts()

    for host, (opts, source, folder) in raw.items():
        hostname, user, port = resolve_connection_fields(host, opts)
        identity = opts.get("identityfile")
        has_pw = host in keychain_accounts
        auth = infer_auth({"identityfile": identity or ""}, has_pw)
        conn = Connection(
            host=host,
            hostname=hostname,
            user=user,
            port=port,
            identity_file=identity,
            auth=auth,
            managed=source.resolve() == managed_path,
            has_password=has_pw,
            folder=folder,
        )
        conn.search_blob = build_search_blob(conn)
        connections.append(conn)

    return connections


def ensure_vnssh_dir() -> None:
    VNSSH_DIR.mkdir(parents=True, exist_ok=True)
    if not HOSTS_CONF.exists():
        HOSTS_CONF.write_text(
            "# Managed by vnssh\n",
            encoding="utf-8",
        )


def is_vnssh_initialized() -> bool:
    """Return True when both managed hosts.conf and ssh config Include exist."""
    if not HOSTS_CONF.exists():
        return False
    return INCLUDE_MARKER in read_config_text(SSH_CONFIG)


def ensure_include() -> None:
    ensure_vnssh_dir()
    ensure_legacy_ip_stanzas()
    ssh_dir = SSH_CONFIG.parent
    ssh_dir.mkdir(parents=True, exist_ok=True)
    text = read_config_text(SSH_CONFIG)
    if INCLUDE_MARKER in text:
        return
    prefix = ""
    if text and not text.endswith("\n"):
        prefix = "\n"
    new_text = f"{INCLUDE_MARKER}\n{prefix}{text}" if text else f"{INCLUDE_MARKER}\n"
    SSH_CONFIG.write_text(new_text, encoding="utf-8")


def format_host_block(data: WizardData) -> str:
    folder = normalize_folder(data.folder)
    lines = [
        f"{FOLDER_COMMENT_PREFIX}{folder}",
        f"Host {data.host}",
        f"    HostName {data.hostname}",
    ]
    if data.user:
        lines.append(f"    User {data.user}")
    port = data.port.strip() or str(DEFAULT_PORT)
    if port != str(DEFAULT_PORT):
        lines.append(f"    Port {port}")
    if data.auth in (AUTH_KEY, AUTH_BOTH):
        identity = data.identity_file.strip() or DEFAULT_IDENTITY
        lines.append(f"    IdentityFile {identity}")
    for key, value in SSH_CONNECT_OPTIONS:
        lines.append(f"    {key} {value}")
    return "\n".join(lines) + "\n"


KNOWN_HOST_BLOCK_KEYS = frozenset(
    {
        "hostname",
        "user",
        "port",
        "identityfile",
        "stricthostkeychecking",
        "connecttimeout",
    }
)


def backup_hosts_conf(path: Path = HOSTS_CONF) -> None:
    if not path.exists():
        return
    backup_path = path.with_name(f"{path.name}.bak")
    shutil.copy2(path, backup_path)


def host_entry_to_wizard(host: str, opts: Dict[str, str], folder: str) -> WizardData:
    identity = opts.get("identityfile", "")
    return WizardData(
        host=host,
        hostname=opts.get("hostname", host),
        user=opts.get("user", ""),
        port=opts.get("port", str(DEFAULT_PORT)),
        folder=folder,
        auth=infer_auth({"identityfile": identity}, keychain_has(host)),
        identity_file=identity or DEFAULT_IDENTITY,
    )


def merged_opts_from_wizard(
    data: WizardData, prior: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    opts: Dict[str, str] = {
        "hostname": data.hostname.strip() or data.host,
        "user": data.user.strip(),
        "port": data.port.strip() or str(DEFAULT_PORT),
    }
    if data.auth in (AUTH_KEY, AUTH_BOTH):
        opts["identityfile"] = data.identity_file.strip() or DEFAULT_IDENTITY
    if prior:
        if prior.get("_vnssh_legacy") == "1":
            opts["_vnssh_legacy"] = "1"
        if prior.get("_vnssh_2fa") == "1" or prior.get("_vnssh_bastion") == "1":
            opts["_vnssh_2fa"] = "1"
        for key, value in prior.items():
            if key.startswith("_") or not value or key in opts:
                continue
            opts[key] = value
    return opts


def format_parsed_host_block(host: str, opts: Dict[str, str], folder: str) -> str:
    block = format_host_block(host_entry_to_wizard(host, opts, folder))
    lines = block.splitlines()
    if lines and lines[0].startswith(FOLDER_COMMENT_PREFIX):
        insert_at = 1
        if opts.get("_vnssh_2fa") == "1":
            lines.insert(insert_at, TWOFA_COMMENT_PREFIX)
            insert_at += 1
        if opts.get("_vnssh_legacy") == "1":
            lines.insert(insert_at, LEGACY_COMMENT_PREFIX)

    extra_lines: List[str] = []
    for key, value in opts.items():
        if key.startswith("_") or not value:
            continue
        if key.lower() in KNOWN_HOST_BLOCK_KEYS:
            continue
        extra_lines.append(f"    {key} {value}")

    if extra_lines:
        insert_at = len(lines)
        for index, line in enumerate(lines):
            if line.strip().lower().startswith("stricthostkeychecking"):
                insert_at = index
                break
        for offset, extra in enumerate(extra_lines):
            lines.insert(insert_at + offset, extra)

    return "\n".join(lines) + "\n"


def write_hosts_conf(
    entries: List[Tuple[str, Dict[str, str], str]], path: Path = HOSTS_CONF
) -> None:
    ensure_vnssh_dir()
    backup_hosts_conf(path)
    parts = ["# Managed by vnssh"]
    for host, opts, folder in dedupe_config_entries(entries):
        parts.append(format_parsed_host_block(host, opts, folder).rstrip())
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def remove_host_block(host: str, path: Path = HOSTS_CONF) -> bool:
    text = read_config_text(path)
    if not text:
        return False
    entries = parse_config_entries(text)
    filtered = [(h, opts, folder) for h, opts, folder in entries if h != host]
    if len(filtered) == len(entries):
        return False
    write_hosts_conf(filtered, path)
    return True


def upsert_host_block(data: WizardData) -> None:
    ensure_vnssh_dir()
    if data.original_host and data.original_host != data.host:
        if keychain_has(data.original_host):
            pw = keychain_get(data.original_host)
            if pw:
                keychain_set(data.host, pw)
            keychain_delete(data.original_host)
        rename_history(data.original_host, data.host)

    text = read_config_text(HOSTS_CONF)
    entries = parse_config_entries(text)
    remove_name = data.original_host or data.host

    prior_opts: Optional[Dict[str, str]] = None
    for host, opts, _folder in entries:
        if host == remove_name:
            prior_opts = opts
            break

    new_entry = (
        data.host,
        merged_opts_from_wizard(data, prior_opts),
        normalize_folder(data.folder),
    )

    new_entries: List[Tuple[str, Dict[str, str], str]] = []
    replaced = False
    for host, opts, folder in entries:
        if host == remove_name:
            if not replaced:
                new_entries.append(new_entry)
                replaced = True
            continue
        new_entries.append((host, opts, folder))
    if not replaced:
        new_entries.append(new_entry)

    write_hosts_conf(dedupe_config_entries(new_entries))


# ---------------------------------------------------------------------------
# Search, sort, filter (with optional pinyin matching)
# ---------------------------------------------------------------------------

_PINYIN_LUT: Optional[Dict[str, str]] = None


def load_pinyin_lut() -> Dict[str, str]:
    global _PINYIN_LUT
    if _PINYIN_LUT is not None:
        return _PINYIN_LUT

    lut: Dict[str, str] = {}
    try:
        payload = gzip.decompress(base64.b64decode(_PINYIN_GZ_B64))
        lut = json.loads(payload.decode("utf-8"))
    except (OSError, json.JSONDecodeError, gzip.BadGzipFile, ValueError):
        lut = {}

    _PINYIN_LUT = lut
    return lut


def pinyin_keys(text: str) -> str:
    """Return full-pinyin and initials strings for mixed Chinese/Latin text."""
    lut = load_pinyin_lut()
    if not lut:
        return ""

    full: List[str] = []
    initials: List[str] = []
    for char in text:
        if "\u4e00" <= char <= "\u9fff":
            syllable = lut.get(char)
            if not syllable:
                continue
            full.append(syllable)
            initials.append(syllable[0])
        elif char.isascii() and char.isalnum():
            lower = char.lower()
            full.append(lower)
            initials.append(lower)

    if not full:
        return ""
    return f"{''.join(full)} {''.join(initials)}"


def build_search_blob(conn: Connection) -> str:
    parts = [
        conn.host,
        conn.hostname,
        conn.user,
        str(conn.port),
        conn.folder_display,
        conn.label,
    ]
    tokens: List[str] = []
    for part in parts:
        if not part:
            continue
        tokens.append(part.lower())
        py = pinyin_keys(part)
        if py:
            tokens.append(py)
    return " ".join(tokens)


def connection_matches(conn: Connection, query: str) -> bool:
    if not query:
        return True
    q = query.lower()
    if q in conn.search_blob:
        return True
    return False


def match_rank(conn: Connection, query: str) -> Tuple[int, float]:
    if not query:
        return (0, -history_score(conn.host))
    q = query.lower()
    host_l = conn.host.lower()
    if host_l == q:
        return (0, -history_score(conn.host))
    if host_l.startswith(q):
        return (1, -history_score(conn.host))
    if q in host_l:
        return (2, -history_score(conn.host))
    if q in (conn.hostname or "").lower():
        return (3, -history_score(conn.host))
    if q in conn.folder_display.lower():
        return (4, -history_score(conn.host))

    py = pinyin_keys(conn.folder_display) + " " + pinyin_keys(conn.host)
    if py and q in py:
        return (5, -history_score(conn.host))
    if q in conn.search_blob:
        return (6, -history_score(conn.host))
    return (7, -history_score(conn.host))


def sorted_connections(connections: List[Connection], query: str) -> List[Connection]:
    filtered = [c for c in connections if connection_matches(c, query)]
    if query:
        filtered.sort(key=lambda c: match_rank(c, query))
    else:
        filtered.sort(key=lambda c: -history_score(c.host))
    return filtered


# ---------------------------------------------------------------------------
# SSH execution
# ---------------------------------------------------------------------------


def askpass_program() -> str:
    """Absolute path used as SSH_ASKPASS (OpenSSH execs this file directly).

    Uses __file__, so copying or renaming the script (e.g. to ~/bin/vnssh)
    still works as long as the file is executable and has a python3 shebang.
    """
    return str(Path(__file__).resolve())


def is_askpass_mode() -> bool:
    # OpenSSH runs SSH_ASKPASS without extra args; VNSSH_HOST marks askpass calls.
    return bool(os.environ.get("VNSSH_HOST"))


def askpass_session_paths(session: str) -> Tuple[Path, Path]:
    counter = VNSSH_DIR / f".askpass-{session}.count"
    lock = VNSSH_DIR / f".askpass-{session}.lock"
    return counter, lock


def cleanup_askpass_session(session: str) -> None:
    if not session:
        return
    counter, lock = askpass_session_paths(session)
    counter.unlink(missing_ok=True)
    lock.unlink(missing_ok=True)


def read_interactive_line_from_tty(*, echo: bool = True) -> Optional[str]:
    """Read one line from the real terminal (2FA / extra kbdint prompts)."""
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return None
    try:
        attrs = termios.tcgetattr(fd)
        saved = termios.tcgetattr(fd)
        attrs[3] |= termios.ICANON
        attrs[3] &= ~termios.NOFLSH
        if echo:
            attrs[3] |= termios.ECHO
        else:
            attrs[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
        chunks: List[bytes] = []
        try:
            while True:
                ch = os.read(fd, 1)
                if not ch or ch in (b"\n", b"\r"):
                    break
                chunks.append(ch)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    finally:
        os.close(fd)
    if not chunks:
        return None
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


def askpass_main() -> None:
    host = os.environ.get("VNSSH_HOST", "")
    session = os.environ.get("VNSSH_ASKPASS_SESSION", str(os.getppid()))
    if not host:
        sys.exit(1)

    VNSSH_DIR.mkdir(parents=True, exist_ok=True)
    counter_path, lock_path = askpass_session_paths(session)
    count = int(counter_path.read_text()) if counter_path.exists() else 0
    counter_path.write_text(str(count + 1))

    if count == 0:
        password = keychain_get(host)
        if password is None:
            sys.exit(1)
        sys.stdout.write(password)
        sys.stdout.flush()
        sys.exit(0)

    # Further keyboard-interactive prompts (2FA, OTP, etc.).
    lock_path.write_text("1")
    try:
        response = read_interactive_line_from_tty(echo=True)
    finally:
        lock_path.unlink(missing_ok=True)
    if not response:
        sys.exit(1)
    sys.stdout.write(response)
    sys.stdout.flush()
    sys.exit(0)


def is_valid_ssh_host_argument(name: str) -> bool:
    """OpenSSH rejects non-ASCII and some punctuation in the hostname argument."""
    if not name:
        return False
    for char in name:
        if char in ".-_:":
            continue
        code = ord(char)
        if 48 <= code <= 57 or 65 <= code <= 90 or 97 <= code <= 122:
            continue
        return False
    return True


def host_legacy_enabled(host: str) -> bool:
    raw = gather_raw_hosts()
    entry = raw.get(host)
    if not entry:
        return False
    return entry[0].get("_vnssh_legacy") == "1"


def host_2fa_enabled(host: str) -> bool:
    raw = gather_raw_hosts()
    entry = raw.get(host)
    if not entry:
        return False
    opts = entry[0]
    return opts.get("_vnssh_2fa") == "1" or opts.get("_vnssh_bastion") == "1"


def legacy_ssh_option_args() -> List[str]:
    args: List[str] = []
    for key, value in LEGACY_SSH_OPTIONS:
        args.extend(["-o", f"{key}={value}"])
    return args


def ssh_algorithm_mismatch(result: ConnectResult) -> bool:
    err = (result.stderr or "").lower()
    phrases = (
        "no matching key exchange method found",
        "no matching cipher found",
        "no matching mac found",
        "no matching host key type found",
    )
    return any(phrase in err for phrase in phrases)


def _probe_network_failure(stderr: str) -> bool:
    err = stderr.lower()
    return any(
        phrase in err
        for phrase in (
            "connection timed out",
            "could not resolve",
            "no route to host",
            "network is unreachable",
            "operation timed out",
        )
    )


def _probe_reached_userauth(result: ConnectResult) -> bool:
    if ssh_algorithm_mismatch(result) or _probe_network_failure(result.stderr or ""):
        return False
    err = (result.stderr or "").lower()
    markers = (
        "permission denied",
        "keyboard-interactive",
        "user authentication",
        "authentication failed",
    )
    return any(marker in err for marker in markers)


def _batch_ssh_base_args(
    host: str,
    *,
    ssh_options: Tuple[Tuple[str, str], ...] = (),
) -> List[str]:
    target, extra = resolve_ssh_endpoint(host)
    args = [
        "ssh",
        "-F",
        "none",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={PROBE_CONNECT_TIMEOUT}",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    for key, value in ssh_options:
        args.extend(["-o", f"{key}={value}"])
    args.extend(extra)
    args.append(target)
    return args


def _probe_batch_ssh(
    host: str,
    ssh_options: Tuple[Tuple[str, str], ...] = (),
) -> Tuple[float, ConnectResult]:
    args = _batch_ssh_base_args(host, ssh_options=ssh_options)
    start = time.monotonic()
    proc = subprocess.run(args, capture_output=True, text=True)
    elapsed = time.monotonic() - start
    return elapsed, ConnectResult(proc.returncode, proc.stderr)


def should_auto_persist_legacy(host: str) -> bool:
    """Decide whether to add #v-legacy without manual tagging."""
    if probe_algorithm_mismatch(host):
        return True
    fast_elapsed, fast_result = _probe_batch_ssh(host, LEGACY_SSH_OPTIONS)
    if not _probe_reached_userauth(fast_result):
        return False
    if fast_elapsed > AUTO_LEGACY_FAST_PROBE_MAX:
        return False
    slow_elapsed, slow_result = _probe_batch_ssh(host)
    if not _probe_reached_userauth(slow_result):
        return True
    return slow_elapsed >= AUTO_LEGACY_SLOW_DEFAULT_MIN


def legacy_session_viable(result: ConnectResult) -> bool:
    """True when a legacy-first interactive attempt reached SSH userauth."""
    return _probe_reached_userauth(result) or (
        result.returncode == 0 and not ssh_algorithm_mismatch(result)
    )


def persist_legacy_host(host: str) -> None:
    """Remember a host needs legacy SSH options after auto-detection."""
    if not HOSTS_CONF.exists():
        return
    text = read_config_text(HOSTS_CONF)
    legacy_prefix = f"{LEGACY_COMMENT_PREFIX}\nHost {host}"
    if legacy_prefix in text:
        return
    pattern = rf"^Host\s+{re.escape(host)}\s*$"
    if not re.search(pattern, text, re.MULTILINE):
        return
    new_text = re.sub(
        pattern,
        f"{LEGACY_COMMENT_PREFIX}\nHost {host}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    HOSTS_CONF.write_text(new_text, encoding="utf-8")
    ensure_legacy_ip_stanzas()


def legacy_ssh_config_lines() -> List[str]:
    return [f"    {key} {value}" for key, value in LEGACY_SSH_OPTIONS]


def format_legacy_ip_stanza(hostname: str, opts: Dict[str, str]) -> str:
    """OpenSSH Host block keyed by IP for plain `ssh user@ip` matching."""
    lines = [f"Host {hostname}", f"    HostName {hostname}"]
    user = opts.get("user", "")
    if user:
        lines.append(f"    User {user}")
    port_str = opts.get("port", str(DEFAULT_PORT))
    try:
        port = int(port_str)
    except ValueError:
        port = DEFAULT_PORT
    if port != DEFAULT_PORT:
        lines.append(f"    Port {port}")
    identity = opts.get("identityfile")
    if identity:
        lines.append(f"    IdentityFile {identity}")
    lines.extend(legacy_ssh_config_lines())
    for key, value in SSH_CONNECT_OPTIONS:
        lines.append(f"    {key} {value}")
    return "\n".join(lines) + "\n"


def ensure_legacy_ip_stanzas() -> None:
    """Ensure legacy network devices have Host <IP> stanzas in hosts.conf."""
    if not HOSTS_CONF.exists():
        return
    text = read_config_text(HOSTS_CONF)
    managed = HOSTS_CONF.resolve()
    additions: List[str] = []

    for host_name, opts, folder in parse_config_entries(text):
        if opts.get("_vnssh_legacy") != "1":
            continue
        hostname = opts.get("hostname", "").strip()
        if not hostname or not re.fullmatch(r"[0-9.]+", hostname):
            continue
        if re.search(rf"^Host\s+{re.escape(hostname)}\s*$", text, re.MULTILINE):
            continue
        additions.append(format_legacy_ip_stanza(hostname, opts))

    if additions:
        if text and not text.endswith("\n"):
            text += "\n"
        HOSTS_CONF.write_text(text + "".join(additions), encoding="utf-8")


def resolve_ssh_endpoint(host: str) -> Tuple[str, List[str]]:
    """Map a config Host alias to an ssh target and extra CLI args."""
    raw = gather_raw_hosts()
    entry = raw.get(host)
    if not entry:
        return host, []

    opts, _, _ = entry
    hostname, user, port = resolve_connection_fields(host, opts)
    extra: List[str] = []
    if port != DEFAULT_PORT:
        extra.extend(["-p", str(port)])
    identity = opts.get("identityfile")
    if identity:
        extra.extend(["-i", os.path.expanduser(identity)])

    if is_valid_ssh_host_argument(host):
        return host, extra

    if hostname:
        target = f"{user}@{hostname}" if user else hostname
        return target, extra

    return host, extra


def askpass_env(host: str, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = (base or os.environ).copy()
    env["VNSSH_HOST"] = host
    env["SSH_ASKPASS"] = askpass_program()
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["DISPLAY"] = env.get("DISPLAY", ":0")
    return env


_CONNECTION_TO_CLOSED = re.compile(
    r"^Connection to .+ closed(\s+by remote host)?\.?$", re.IGNORECASE
)

_DISCONNECT_LINE = (
    _CONNECTION_TO_CLOSED,
    re.compile(r"^Shared connection to .+ closed\.?$", re.IGNORECASE),
    re.compile(r"^Connection closed by .+ port \d+", re.IGNORECASE),
    re.compile(r"^Disconnected from .+ port \d+", re.IGNORECASE),
)


def is_ssh_noise_line(line: str) -> bool:
    lower = line.lower()
    if line.startswith("Warning:") or line.startswith("**"):
        return True
    if "post-quantum key exchange" in lower:
        return True
    if "Pseudo-terminal will not be allocated" in line:
        return True
    return False


def is_disconnect_line(line: str) -> bool:
    return any(pattern.search(line) for pattern in _DISCONNECT_LINE)


def is_normal_ssh_disconnect(err: str) -> bool:
    """Detect normal logout from the last substantive line SSH prints."""
    lines = [line.strip() for line in err.splitlines() if line.strip()]
    if not lines:
        return True
    kept = [line for line in lines if not is_ssh_noise_line(line)]
    if not kept:
        return True
    last = kept[-1]
    # Printed after an interactive logout; not a connect-time failure.
    if _CONNECTION_TO_CLOSED.search(last):
        return True
    if not is_disconnect_line(last):
        return False
    # Other disconnect lines are normal only when a shell session actually ran
    # (PTY scrollback). With no session output they usually mean wrong port/VPN.
    session_lines = [line for line in kept[:-1] if not is_disconnect_line(line)]
    return bool(session_lines)


def connect_failure_snippet(err: str) -> str:
    """Prefer the last non-noise lines for status-bar errors (ignore shell scrollback)."""
    lines = [line.strip() for line in err.splitlines() if line.strip()]
    kept = [line for line in lines if not is_ssh_noise_line(line)]
    if not kept:
        return err.strip()
    for line in reversed(kept):
        if line.lower().startswith("received disconnect from"):
            return line
    return "\n".join(kept[-3:])


_SSH_DISCONNECT_REASON = re.compile(
    r"^Received disconnect from .+ port \d+:\d+:\s*(.+?)\s*$",
    re.IGNORECASE,
)


def ssh_disconnect_reason(err: str) -> Optional[str]:
    for line in err.splitlines():
        match = _SSH_DISCONNECT_REASON.match(line.strip())
        if match:
            return match.group(1).strip()
    return None


def password_expired_error(err: str, host: str) -> Optional[str]:
    if not err:
        return None
    expired_msg = (
        f"{host}: password expired (reset on bastion portal or contact admin)"
    )
    compact = err.lower().replace(" ", "").replace("_", "")
    if "passwordexpired" in compact or "passwordhasexpired" in compact:
        return expired_msg
    lower = err.lower()
    if "password expired" in lower or "password has expired" in lower:
        return expired_msg
    if "\u5bc6\u7801\u8fc7\u671f" in err or "\u5bc6\u7801\u5df2\u8fc7\u671f" in err:
        return expired_msg
    reason = ssh_disconnect_reason(err)
    if reason and "passwordexpired" in reason.lower().replace(" ", ""):
        return expired_msg
    return None


def ssh_disconnect_error(err: str, host: str) -> Optional[str]:
    expired = password_expired_error(err, host)
    if expired:
        return expired
    reason = ssh_disconnect_reason(err)
    if not reason:
        return None
    lower = reason.lower()
    if lower == "authentication failed":
        return (
            f"{host}: authentication failed "
            f"(wrong password, or password expired on bastion)"
        )
    if lower == "too many authentication failures":
        return f"{host}: too many authentication failures"
    return f"{host}: {reason}"


def identity_key_error(err: str, host: str) -> Optional[str]:
    """Detect OpenSSH private-key file permission/path errors in full stderr."""
    if not err:
        return None
    lower = err.lower()
    markers = (
        "unprotected private key file",
        "are too open",
        "bad permissions",
        "private key will be ignored",
        "identity file",
        "not accessible",
        "load key",
    )
    if not any(marker in lower for marker in markers):
        return None

    key_path = ""
    for line in err.splitlines():
        text = line.strip()
        match = re.search(
            r"Permissions \d+ for '([^']+)' are too open", text, re.IGNORECASE
        )
        if match:
            key_path = match.group(1)
            break
        match = re.search(r'Load key "([^"]+)": bad permissions', text, re.IGNORECASE)
        if match:
            key_path = match.group(1)
            break
        match = re.search(r"Identity file ([^ ]+) not accessible", text, re.IGNORECASE)
        if match:
            key_path = match.group(1)
            break

    if not key_path:
        entry = gather_raw_hosts().get(host)
        if entry:
            key_path = entry[0].get("identityfile", "")

    if key_path:
        key_path = os.path.expanduser(key_path)
        if "not accessible" in lower and "too open" not in lower:
            return (
                f"{host}: private key not found or not readable ({key_path}); "
                f"check path and run: chmod 600 '{key_path}'"
            )
        return (
            f"{host}: private key permissions too open ({key_path}); "
            f"run: chmod 600 '{key_path}'"
        )
    return (
        f"{host}: private key file permissions too open or not accessible; "
        f"run: chmod 600 <key.pem>"
    )


def should_report_connect_error(result: ConnectResult) -> bool:
    """Only surface status-bar errors for real failures, not normal SSH logout."""
    if result.returncode == 0:
        return False
    if result.returncode == 130:
        return False
    err = (result.stderr or "").strip()
    if is_normal_ssh_disconnect(err):
        return False
    return bool(connect_failure_snippet(err))


def format_connect_error(host: str, result: ConnectResult) -> str:
    full_err = (result.stderr or "").strip()
    key_err = identity_key_error(full_err, host)
    if key_err:
        return key_err
    disconnect_err = ssh_disconnect_error(full_err, host)
    if disconnect_err:
        return disconnect_err
    err = connect_failure_snippet(full_err)

    if "Permission denied" in err:
        mode = connection_auth_mode(host)
        if mode == AUTH_KEY:
            return (
                f"{host}: authentication failed "
                f"(check private key path, permissions, or key itself)"
            )
        if not keychain_has(host):
            return f"{host}: authentication failed (no saved password; press e to store)"
        return f"{host}: authentication failed (check password or key)"
    if "no matching key exchange" in err:
        return f"{host}: SSH algorithm mismatch"
    if "Host key verification failed" in err:
        return f"{host}: host key verification failed"
    if "Could not resolve hostname" in err:
        return f"{host}: hostname could not be resolved"
    for phrase in ("Connection refused", "Operation timed out", "Connection timed out"):
        if phrase in err:
            return f"{host}: {phrase.lower()} (try another port or check VPN)"
    if "Connection closed by" in err or "kex_exchange_identification" in err:
        return (
            f"{host}: server closed connection "
            f"(try another port, or check VPN/firewall)"
        )
    if "Connection reset" in err or "Broken pipe" in err:
        return f"{host}: network connection dropped (try another port or check VPN)"
    for line in reversed(err.splitlines()):
        text = line.strip()
        if not text or text.startswith("Warning:"):
            continue
        if "Pseudo-terminal will not be allocated" in text:
            continue
        if "post-quantum key exchange" in text:
            continue
        if text.lower().startswith("received disconnect from"):
            continue
        if is_disconnect_line(text):
            continue
        return f"{host}: {text[:100]}"
    if result.returncode != 0:
        return f"{host}: connection failed (try another port, or check VPN/network)"
    return f"{host}: connection closed"


def build_ssh_argv(host: str, *, legacy: Optional[bool] = None) -> List[str]:
    args = ["ssh"]
    for key, value in SSH_CONNECT_OPTIONS:
        args.extend(["-o", f"{key}={value}"])
    raw = gather_raw_hosts()
    entry = raw.get(host)
    opts = entry[0] if entry else {}
    use_legacy = legacy if legacy is not None else opts.get("_vnssh_legacy") == "1"
    mode = connection_auth_mode(host)
    if mode == AUTH_PASSWORD and keychain_has(host):
        args.extend(
            [
                "-o",
                "PreferredAuthentications=keyboard-interactive,password",
                "-o",
                "PubkeyAuthentication=no",
            ]
        )
    if use_legacy:
        args.extend(legacy_ssh_option_args())
    target, extra = resolve_ssh_endpoint(host)
    args.extend(extra)
    args.append(target)
    return args


def probe_algorithm_mismatch(host: str) -> bool:
    """Detect old SSH algorithms without user config or authentication."""
    args = _batch_ssh_base_args(
        host,
        ssh_options=(
            ("KexAlgorithms", "curve25519-sha256,diffie-hellman-group16-sha512"),
        ),
    )
    proc = subprocess.run(args, capture_output=True, text=True)
    return ssh_algorithm_mismatch(ConnectResult(proc.returncode, proc.stderr))


def open_controlling_tty() -> Optional[int]:
    """Return a fd for the real terminal (works after curses endwin)."""
    try:
        return os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return None


def set_terminal_title(title: str) -> None:
    """Set Ghostty/xterm window title via OSC sequences."""
    if not title:
        return
    safe = title.replace("\x1b", "").replace("\x07", "")
    try:
        fd = os.open("/dev/tty", os.O_WRONLY)
    except OSError:
        return
    try:
        payload = f"\033]0;{safe}\007\033]2;{safe}\007".encode("utf-8")
        os.write(fd, payload)
    except OSError:
        pass
    finally:
        os.close(fd)


def clear_terminal_screen() -> None:
    """Erase physical terminal content left by SSH (incl. alternate screen)."""
    try:
        fd = os.open("/dev/tty", os.O_WRONLY)
    except OSError:
        return
    try:
        os.write(fd, b"\033[?1049l\033[2J\033[H")
    except OSError:
        pass
    finally:
        os.close(fd)


def prepare_terminal_for_shell() -> None:
    """Restore canonical terminal mode after curses endwin()."""
    tty_fd = open_controlling_tty()
    fd = tty_fd if tty_fd is not None else sys.stdin.fileno()
    if tty_fd is None and not sys.stdin.isatty():
        return
    try:
        attrs = termios.tcgetattr(fd)
        attrs[3] |= termios.ICANON | termios.ECHO
        attrs[3] &= ~termios.NOFLSH
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
    except (OSError, termios.error):
        pass
    finally:
        if tty_fd is not None:
            os.close(tty_fd)


def sync_pty_window_size(master_fd: int, tty_fd: int) -> None:
    try:
        buf = fcntl.ioctl(tty_fd, termios.TIOCGWINSZ, b"\0" * 8)
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, buf)
    except OSError:
        pass


def restore_tty_attrs(fd: int, attrs: Optional[List]) -> None:
    if attrs is None:
        return
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
    except (OSError, termios.error):
        pass


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_TWOFA_PASSWORD_PROMPT_MARKERS = (
    re.compile(r"(?i)please input password"),
    re.compile(r"(?i)password of operation account"),
    re.compile(r"(?i)\[LOGIN\].*password"),
)

_OPENSSH_PASSWORD_PROMPT = re.compile(r"(?i)(?:'s|\u2019s) password:\s*$")

_VERIFICATION_PROMPT_MARKERS = (
    re.compile(r"(?i)verification\s*code"),
    re.compile(r"(?i)\botp\b"),
    re.compile(r"(?i)one[- ]time"),
    re.compile(r"(?i)2fa"),
    re.compile(r"(?i)mfa"),
    re.compile(r"(?i)dynamic\s+password"),
    re.compile(r"(?i)auth(?:entication)?\s*code"),
    re.compile(r"(?i)\btoken\b"),
    re.compile(r"\u9a8c\u8bc1\u7801"),
    re.compile(r"\u4e8c\u6b21\u9a8c\u8bc1"),
    re.compile(r"\u52a8\u6001\u53e3\u4ee4"),
)

_AUTH_FAILURE_MARKERS = (
    re.compile(r"(?i)password\s*expired"),
    re.compile(r"(?i)passwordexpired"),
    re.compile(r"(?i)received disconnect"),
    re.compile(r"(?i)authentication failed"),
    re.compile(r"\u5bc6\u7801\u8fc7\u671f"),
)

_AUTO_PASSWORD_DELAY = 0.45
_SESSION_LOG_READY_DELAY = 0.4
_RECENT_OUTPUT_WINDOW = 16384
_LOG_FLUSH_BYTES = 1024
_LOG_FLUSH_INTERVAL = 0.05

_SSH_CLIENT_MARKERS = (
    re.compile(r"(?i)the authenticity of host"),
    re.compile(r"(?i)are you sure you want to continue connecting"),
    re.compile(r"(?i)warning: permanently added"),
)


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


def _recent_output_lines(recent_text: str, *, tail: int = 8) -> List[str]:
    clean = _strip_ansi(recent_text)
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    return lines[-tail:]


def _has_auth_failure(recent_text: str) -> bool:
    clean = _strip_ansi(recent_text)
    return any(marker.search(clean) for marker in _AUTH_FAILURE_MARKERS)


def _prompt_line_complete(line: str) -> bool:
    if line.endswith(":") or line.endswith("：") or line.endswith("..."):
        return True
    return any(marker.search(line) for marker in _TWOFA_PASSWORD_PROMPT_MARKERS)


def _password_prompt_signature(
    recent_text: str, *, allow_standard_password: bool = False
) -> Optional[str]:
    if _has_auth_failure(recent_text):
        return None
    tail = _strip_ansi(recent_text)[-2000:]
    if any(marker.search(tail) for marker in _VERIFICATION_PROMPT_MARKERS):
        return None
    for line in reversed(_recent_output_lines(recent_text)):
        if any(marker.search(line) for marker in _VERIFICATION_PROMPT_MARKERS):
            return None
        if any(marker.search(line) for marker in _TWOFA_PASSWORD_PROMPT_MARKERS):
            return line if _prompt_line_complete(line) else None
        if allow_standard_password and _OPENSSH_PASSWORD_PROMPT.search(line):
            return line
    return None


def _has_active_verification_prompt(recent_text: str) -> bool:
    """True while recent output still contains an OTP/2FA prompt."""
    for line in _recent_output_lines(recent_text, tail=4):
        if any(marker.search(line) for marker in _VERIFICATION_PROMPT_MARKERS):
            return True
    return False


def _bastion_ui_visible(recent_text: str) -> bool:
    clean = _strip_ansi(recent_text)
    return bool(_BASTION_UI_MARKER.search(clean))


def _parse_nested_login_success(recent_bytes: bytes) -> Optional[Tuple[str, int, str]]:
    """Match nested login success in recent PTY output (handles TCP chunk splits)."""
    if not recent_bytes:
        return None
    match = _NESTED_LOGIN_OK.search(recent_bytes[-4096:])
    if not match:
        return None
    return match.group(1).decode("utf-8", errors="replace"), int(match.group(2)), (
        match.group(3).decode("utf-8", errors="replace")
    )


def _session_ready_for_log(
    recent_text: str,
    *,
    auto_password: bool,
    password_sent: bool,
    twofa_enabled: bool = False,
) -> bool:
    tail = _strip_ansi(recent_text)[-2000:]
    if any(marker.search(tail) for marker in _AUTH_FAILURE_MARKERS):
        return False
    if _password_prompt_signature(recent_text, allow_standard_password=True):
        return False
    if _has_active_verification_prompt(recent_text):
        return False
    if (auto_password or twofa_enabled) and not password_sent:
        return False
    if len(tail.strip()) < 8:
        return False
    recent_lines = _recent_output_lines(recent_text, tail=6)
    if recent_lines and all(
        any(marker.search(line) for marker in _SSH_CLIENT_MARKERS) for line in recent_lines
    ):
        return False
    return True


def clear_askpass_env(env: Dict[str, str]) -> None:
    for var in (
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "VNSSH_HOST",
        "VNSSH_ASKPASS_SESSION",
        "VNSSH_AUTO_PASSWORD_HOST",
        "VNSSH_AUTH_MODE",
    ):
        env.pop(var, None)


def session_logging_enabled() -> bool:
    token = os.environ.get("VNSSH_SESSION_LOG", "1").strip().lower()
    return token not in ("0", "false", "no", "off")


def sanitize_log_component(text: str, *, max_len: int = 56) -> str:
    cleaned = re.sub(r"[^\w\-.@+]+", "_", text.strip())
    cleaned = cleaned.strip("._") or "host"
    return cleaned[:max_len]


def session_endpoint_fields(host: str) -> Dict[str, object]:
    entry = gather_raw_hosts().get(host)
    opts = entry[0] if entry else {}
    hostname, user, port = resolve_connection_fields(host, opts)
    endpoint = f"{user}@{hostname}" if user else hostname
    return {
        "host": host,
        "hostname": hostname,
        "user": user,
        "port": port,
        "endpoint": endpoint,
    }


def allocate_session_log_path(host: str, started: datetime) -> Path:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    fields = session_endpoint_fields(host)
    endpoint = str(fields["endpoint"])
    port = int(fields["port"])
    stamp = started.strftime("%Y-%m-%d_%H%M%S")
    base = (
        f"{sanitize_log_component(host)}_"
        f"{sanitize_log_component(endpoint)}"
    )
    if port != DEFAULT_PORT:
        base += f"_p{port}"
    suffix = 0
    while True:
        name = f"{base}_{stamp}" if suffix == 0 else f"{base}_{stamp}_{suffix}"
        transcript = SESSIONS_DIR / f"{name}.session"
        if not transcript.exists():
            return transcript
        suffix += 1


def allocate_nested_session_log_path(
    bastion_host: str,
    *,
    target_host: str,
    target_user: str,
    target_port: int,
    started: datetime,
) -> Path:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y-%m-%d_%H%M%S")
    base = (
        f"{sanitize_log_component(target_host)}_"
        f"{sanitize_log_component(target_user)}"
        f"_via_{sanitize_log_component(bastion_host)}"
    )
    if target_port != DEFAULT_PORT:
        base += f"_p{target_port}"
    suffix = 0
    while True:
        name = f"{base}_{stamp}" if suffix == 0 else f"{base}_{stamp}_{suffix}"
        transcript = SESSIONS_DIR / f"{name}.session"
        if not transcript.exists():
            return transcript
        suffix += 1


_SESSION_LOG_CSI = re.compile(rb"(?:\x1b|\x9b)[\[\(][0-9;?]*[ -/]*[@-~]")
_SESSION_LOG_OSC = re.compile(rb"\x1b\][^\x07]*(?:\x07|\x1b\\)")
_SESSION_LOG_MORE = re.compile(rb"-{2,}\s*More\s*-{2,}\s*", re.IGNORECASE)
_SESSION_LOG_MORE_ALT = re.compile(rb"--\s*More\s*--\s*", re.IGNORECASE)
_SESSION_LOG_ORPHAN_SGR = re.compile(rb"(?:;\d+)+m|\d+m")
_BASTION_UI_MARKER = re.compile(r"TencentCloud BastionHost|BastionHost", re.I)
_NESTED_LOGIN_OK = re.compile(
    rb"login to (\S+?):(\d+) with account (\S+) success", re.IGNORECASE
)
_NESTED_LOGOUT = re.compile(rb"logout from \S+@\S+:\d+", re.IGNORECASE)


def _sanitize_session_log_chunk(data: bytes) -> bytes:
    if not data:
        return b""
    cleaned = _SESSION_LOG_CSI.sub(b"", data)
    cleaned = _SESSION_LOG_OSC.sub(b"", cleaned)
    cleaned = _SESSION_LOG_MORE.sub(b"", cleaned)
    cleaned = _SESSION_LOG_MORE_ALT.sub(b"", cleaned)
    return cleaned


def _normalize_session_log_chunk(data: bytes) -> bytes:
    if not data:
        return b""
    cleaned = _sanitize_session_log_chunk(data)
    cleaned = _SESSION_LOG_ORPHAN_SGR.sub(b"", cleaned)
    cleaned = cleaned.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return cleaned


class SessionLogSanitizer:
    """Strip pager prompts and terminal control sequences from session logs."""

    _HOLD_BACK = 16

    def __init__(self) -> None:
        self._pending = bytearray()

    def feed(self, data: bytes) -> bytes:
        if not data:
            return b""
        self._pending.extend(data)
        if len(self._pending) <= self._HOLD_BACK:
            return b""
        emit_len = len(self._pending) - self._HOLD_BACK
        emit = bytes(self._pending[:emit_len])
        del self._pending[:emit_len]
        return _normalize_session_log_chunk(emit)

    def flush(self) -> bytes:
        if not self._pending:
            return b""
        cleaned = _normalize_session_log_chunk(bytes(self._pending))
        self._pending.clear()
        return cleaned


def sanitize_session_log_file(transcript_path: Path) -> None:
    try:
        raw = transcript_path.read_bytes()
    except OSError:
        return
    if not raw:
        return
    sanitizer = SessionLogSanitizer()
    cleaned = bytearray()
    for offset in range(0, len(raw), 65536):
        cleaned.extend(sanitizer.feed(raw[offset : offset + 65536]))
    cleaned.extend(sanitizer.flush())
    payload = bytes(cleaned)
    if payload == raw:
        return
    try:
        transcript_path.write_bytes(payload)
    except OSError:
        pass


def begin_session_log(host: str) -> Optional[Path]:
    if not session_logging_enabled():
        return None
    return allocate_session_log_path(host, datetime.now().astimezone())


SESSION_ARCHIVE_STATE_FILE = SESSIONS_DIR / ".archive-state.json"
_SESSION_FILE_DATE_RE = re.compile(r"_(\d{4}-\d{2}-\d{2})_\d{6}(?:_\d+)?\.session$")


def session_archive_enabled() -> bool:
    token = os.environ.get("VNSSH_SESSION_ARCHIVE", "1").strip().lower()
    return token not in ("0", "false", "no", "off")


def session_file_date(path: Path) -> Optional[date]:
    match = _SESSION_FILE_DATE_RE.search(path.name)
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def week_label_for(day: date) -> str:
    monday = day - timedelta(days=day.weekday())
    sunday = monday + timedelta(days=6)
    return f"{monday.isoformat()}_{sunday.isoformat()}"


def current_week_monday() -> date:
    today = datetime.now().astimezone().date()
    return today - timedelta(days=today.weekday())


def load_session_archive_state() -> set[str]:
    if not SESSION_ARCHIVE_STATE_FILE.exists():
        return set()
    try:
        payload = json.loads(
            SESSION_ARCHIVE_STATE_FILE.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return set()
    weeks = payload.get("archived_weeks", [])
    if not isinstance(weeks, list):
        return set()
    return {str(item) for item in weeks}


def save_session_archive_state(archived_weeks: set[str]) -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"archived_weeks": sorted(archived_weeks)}
    SESSION_ARCHIVE_STATE_FILE.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


def find_pending_session_archive_weeks() -> List[str]:
    """Return sorted week labels (Mon_Sun) before the current week needing archive."""
    if not session_archive_enabled() or not SESSIONS_DIR.exists():
        return []
    archived = load_session_archive_state()
    current_monday = current_week_monday()
    pending: set[str] = set()
    for path in SESSIONS_DIR.glob("*.session"):
        file_date = session_file_date(path)
        if file_date is None:
            continue
        week_monday = file_date - timedelta(days=file_date.weekday())
        if week_monday >= current_monday:
            continue
        label = week_label_for(file_date)
        if label not in archived:
            pending.add(label)
    return sorted(pending)


def list_session_files_for_week_label(week_label: str) -> List[Path]:
    files: List[Path] = []
    for path in SESSIONS_DIR.glob("*.session"):
        file_date = session_file_date(path)
        if file_date is None:
            continue
        if week_label_for(file_date) == week_label:
            files.append(path)
    return sorted(files)


def archive_session_week(week_label: str, files: List[Path]) -> bool:
    if not files:
        return True
    archive_path = SESSIONS_DIR / f"{week_label}.tar.gz"
    tmp_path = SESSIONS_DIR / f"{week_label}.tar.gz.tmp"
    tmp_path.unlink(missing_ok=True)
    names = [path.name for path in files]
    try:
        subprocess.run(
            ["tar", "-czf", str(tmp_path), "-C", str(SESSIONS_DIR), *names],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        tmp_path.unlink(missing_ok=True)
        return False
    try:
        archive_path.unlink(missing_ok=True)
        tmp_path.replace(archive_path)
        for path in files:
            path.unlink()
    except OSError:
        tmp_path.unlink(missing_ok=True)
        return False
    return True


def archive_pending_session_weeks(week_labels: List[str]) -> None:
    """Pack prior-week session logs on TUI exit; delete sources after success."""
    if not session_archive_enabled() or not week_labels:
        return
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    archived = load_session_archive_state()
    for week_label in week_labels:
        if week_label in archived:
            continue
        files = list_session_files_for_week_label(week_label)
        if not files:
            archived.add(week_label)
            save_session_archive_state(archived)
            continue
        print(f"Archiving sessions {week_label}...", file=sys.stderr, flush=True)
        if archive_session_week(week_label, files):
            archived.add(week_label)
            save_session_archive_state(archived)
            print(
                f"Archived {len(files)} session(s) -> {week_label}.tar.gz",
                file=sys.stderr,
                flush=True,
            )
        else:
            print(
                f"Failed to archive sessions {week_label}; will retry next run",
                file=sys.stderr,
                flush=True,
            )


def run_ssh_with_tty(
    argv: List[str],
    env: Dict[str, str],
    *,
    transcript_path: Optional[Path] = None,
    session_host: str = "",
) -> Tuple[int, str]:
    """Run ssh on a pty; relay via /dev/tty so prompts work after curses."""
    askpass_session = env.get("VNSSH_ASKPASS_SESSION", "")
    _, askpass_lock = (
        askpass_session_paths(askpass_session)
        if askpass_session
        else (None, None)
    )

    auto_password_host = env.get("VNSSH_AUTO_PASSWORD_HOST", "")
    auto_password_auth_mode = env.get("VNSSH_AUTH_MODE", AUTH_PASSWORD)
    twofa_enabled = bool(
        auto_password_host and host_2fa_enabled(auto_password_host)
    )
    auto_password: Optional[str] = None
    if auto_password_host and keychain_has(auto_password_host):
        auto_password = keychain_get(auto_password_host)
    password_sent = False
    password_pending_since: Optional[float] = None
    password_prompt_sig: Optional[str] = None
    tty_fd = open_controlling_tty()
    if tty_fd is None and not sys.stdin.isatty():
        proc = subprocess.run(argv, env=env, capture_output=True, text=True)
        err = (proc.stderr or proc.stdout or "").strip()
        return proc.returncode, err

    output = bytearray()
    pid, master_fd = pty.fork()
    if pid == 0:
        if tty_fd is not None:
            os.close(tty_fd)
        os.execvpe(argv[0], argv, env)

    if tty_fd is not None:
        sync_pty_window_size(master_fd, tty_fd)
        terminal_fd = tty_fd
    else:
        terminal_fd = sys.stdin.fileno()
        tty_fd = None

    saved_tty: Optional[List] = None
    resize_pending = False
    old_winch = signal.SIG_DFL

    def on_winch(signum: int, frame: Optional[object]) -> None:
        nonlocal resize_pending
        resize_pending = True

    def tick_auto_password() -> None:
        nonlocal password_sent, password_pending_since, password_prompt_sig
        if not auto_password or password_sent or not recent_output:
            return
        sig = _password_prompt_signature(
            recent_output,
            allow_standard_password=auto_password_auth_mode
            in (AUTH_PASSWORD, AUTH_BOTH),
        )
        if not sig:
            password_pending_since = None
            password_prompt_sig = None
            return
        now = time.monotonic()
        if password_prompt_sig != sig:
            password_prompt_sig = sig
            password_pending_since = now
            return
        if (
            password_pending_since is not None
            and now - password_pending_since >= _AUTO_PASSWORD_DELAY
        ):
            password_sent = True
            payload = (auto_password + "\n").encode("utf-8")
            os.write(master_fd, payload)
            output.extend(payload)
            password_pending_since = None

    log_file: Optional[object] = None
    logging_active = False
    log_ready_since: Optional[float] = None
    initial_auth_done = False
    bastion_ui_seen = False
    log_write_buffer = bytearray()
    last_log_flush = 0.0
    log_enabled = session_logging_enabled() and bool(session_host)
    log_sanitizer: Optional[SessionLogSanitizer] = None
    active_transcript_path = transcript_path

    def flush_session_log_buffer(*, force: bool = False) -> None:
        nonlocal last_log_flush
        if log_file is None or not log_write_buffer:
            return
        now = time.monotonic()
        if (
            not force
            and len(log_write_buffer) < _LOG_FLUSH_BYTES
            and now - last_log_flush < _LOG_FLUSH_INTERVAL
        ):
            return
        log_file.write(log_write_buffer)
        log_file.flush()
        log_write_buffer.clear()
        last_log_flush = now

    def finalize_session_log_file(*, sanitize: bool = True) -> None:
        nonlocal log_file, logging_active, log_sanitizer
        if log_file is None:
            return
        if log_sanitizer is not None:
            try:
                pending = log_sanitizer.flush()
                if pending:
                    log_write_buffer.extend(pending)
            except OSError:
                pass
        try:
            flush_session_log_buffer(force=True)
            log_file.close()
        except OSError:
            pass
        if sanitize and active_transcript_path is not None:
            sanitize_session_log_file(active_transcript_path)
        log_file = None
        logging_active = False
        log_sanitizer = None

    def open_session_log(path: Path) -> bool:
        nonlocal log_file, logging_active, log_sanitizer, active_transcript_path
        nonlocal last_log_flush
        finalize_session_log_file(sanitize=True)
        try:
            log_file = path.open("ab", buffering=0)
        except OSError:
            return False
        active_transcript_path = path
        log_sanitizer = SessionLogSanitizer()
        logging_active = True
        last_log_flush = time.monotonic()
        return True

    def write_session_log(data: bytes) -> None:
        if not logging_active or log_file is None:
            return
        cleaned = (
            log_sanitizer.feed(data)
            if log_sanitizer is not None
            else _normalize_session_log_chunk(data)
        )
        if cleaned:
            log_write_buffer.extend(cleaned)
            flush_session_log_buffer()

    def try_start_nested_session_log(data: bytes) -> bool:
        if not log_enabled or not session_host or not bastion_ui_seen:
            return False
        parsed = _parse_nested_login_success(bytes(output))
        if parsed is None:
            return False
        target_host, target_port, target_user = parsed
        nested_path = allocate_nested_session_log_path(
            session_host,
            target_host=target_host,
            target_user=target_user,
            target_port=target_port,
            started=datetime.now().astimezone(),
        )
        return open_session_log(nested_path)

    def try_start_direct_session_log() -> bool:
        nonlocal log_ready_since, initial_auth_done, active_transcript_path
        if not log_enabled or logging_active or bastion_ui_seen:
            return False
        if askpass_lock is not None and askpass_lock.exists():
            log_ready_since = None
            return False
        if not initial_auth_done:
            if not _session_ready_for_log(
                recent_output,
                auto_password=bool(auto_password),
                password_sent=password_sent,
                twofa_enabled=twofa_enabled,
            ):
                log_ready_since = None
                return False
            initial_auth_done = True
        now = time.monotonic()
        if log_ready_since is None:
            log_ready_since = now
            return False
        if now - log_ready_since < _SESSION_LOG_READY_DELAY:
            return False
        if active_transcript_path is None:
            active_transcript_path = begin_session_log(session_host)
            if active_transcript_path is None:
                return False
        return open_session_log(active_transcript_path)

    def update_session_log(data: bytes) -> None:
        nonlocal bastion_ui_seen
        if not log_enabled:
            return
        if _bastion_ui_visible(recent_output):
            bastion_ui_seen = True
        if logging_active:
            if bastion_ui_seen and _NESTED_LOGOUT.search(bytes(output[-2048:])):
                write_session_log(data)
                flush_session_log_buffer(force=True)
                if log_sanitizer is not None:
                    pending = log_sanitizer.flush()
                    if pending:
                        log_write_buffer.extend(pending)
                flush_session_log_buffer(force=True)
                finalize_session_log_file()
                return
            write_session_log(data)
            return
        if try_start_nested_session_log(data):
            write_session_log(data)
            flush_session_log_buffer(force=True)
            return
        if try_start_direct_session_log():
            write_session_log(data)

    try:
        saved_tty = termios.tcgetattr(terminal_fd)
        tty.setraw(terminal_fd, termios.TCSADRAIN)
        old_winch = signal.signal(signal.SIGWINCH, on_winch)
        recent_output = ""
        while True:
            if resize_pending:
                resize_pending = False
                sync_pty_window_size(master_fd, terminal_fd)
            relay_fds = [master_fd]
            if askpass_lock is None or not askpass_lock.exists():
                relay_fds.append(terminal_fd)
            readable, _, _ = select.select(relay_fds, [], [], 0.2)
            if logging_active:
                flush_session_log_buffer()
            if master_fd in readable:
                try:
                    data = os.read(master_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                output.extend(data)
                os.write(terminal_fd, data)
                if len(output) > _RECENT_OUTPUT_WINDOW:
                    del output[: len(output) - _RECENT_OUTPUT_WINDOW]
                recent_output = output.decode("utf-8", errors="replace")
                update_session_log(data)
            tick_auto_password()
            if terminal_fd in readable:
                try:
                    data = os.read(terminal_fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                os.write(master_fd, data)
    finally:
        signal.signal(signal.SIGWINCH, old_winch)
        restore_tty_attrs(terminal_fd, saved_tty)
        finalize_session_log_file()
        if tty_fd is not None:
            os.close(tty_fd)
        os.close(master_fd)
        _, status = os.waitpid(pid, 0)

    err_text = output.decode("utf-8", errors="replace").strip()
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status), err_text
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status), err_text
    return 1, err_text


def prepare_ssh_invocation(
    host: str, *, legacy: bool, use_keychain: bool, interactive: bool = True
) -> Tuple[List[str], Dict[str, str], bool, bool]:
    ssh_args = build_ssh_argv(host, legacy=legacy)
    env = os.environ.copy()
    use_askpass, use_pty_inject = (
        password_delivery_mode(host, interactive=interactive)
        if use_keychain
        else (False, False)
    )
    if use_askpass:
        env = askpass_env(host, env)
    else:
        clear_askpass_env(env)
        if interactive and "-tt" not in ssh_args:
            ssh_args.insert(1, "-tt")
    return ssh_args, env, use_askpass, use_pty_inject


def run_ssh_session(
    ssh_args: List[str],
    env: Dict[str, str],
    use_askpass: bool,
    exec_mode: bool,
    *,
    host: str = "",
    use_pty_password_inject: bool = False,
) -> ConnectResult:
    args = list(ssh_args)
    run_env = dict(env)
    session = ""
    if use_askpass:
        session = secrets.token_hex(8)
        run_env["VNSSH_ASKPASS_SESSION"] = session
        cleanup_askpass_session(session)
    elif use_pty_password_inject and host:
        run_env["VNSSH_AUTO_PASSWORD_HOST"] = host
        run_env["VNSSH_AUTH_MODE"] = connection_auth_mode(host)
    else:
        clear_askpass_env(run_env)
    if use_askpass or use_pty_password_inject:
        if "-tt" not in args:
            args.insert(1, "-tt")
    elif "-tt" not in args:
        args.insert(1, "-tt")

    defer_session_log = bool(host and host_2fa_enabled(host))
    transcript_path = (
        None if defer_session_log else (begin_session_log(host) if host else None)
    )

    if exec_mode:
        os.execvpe(args[0], args, run_env)

    returncode = 1
    stderr = ""
    try:
        returncode, stderr = run_ssh_with_tty(
            args,
            run_env,
            transcript_path=transcript_path,
            session_host=host,
        )
    finally:
        cleanup_askpass_session(session)
    return ConnectResult(returncode, stderr=stderr)


def _run_interactive_ssh(
    host: str, *, legacy: bool, use_keychain: bool
) -> ConnectResult:
    ssh_args, env, use_askpass, use_pty_inject = prepare_ssh_invocation(
        host, legacy=legacy, use_keychain=use_keychain, interactive=True
    )
    return run_ssh_session(
        ssh_args,
        env,
        use_askpass,
        exec_mode=False,
        host=host,
        use_pty_password_inject=use_pty_inject,
    )


def connect_host(
    host: str, use_keychain: bool = True, exec_mode: bool = True
) -> ConnectResult:
    """Run ssh. exec_mode=True replaces process (CLI); TUI returns exit code."""
    record_use(host)
    legacy = host_legacy_enabled(host)

    if exec_mode:
        if not legacy and should_auto_persist_legacy(host):
            persist_legacy_host(host)
            legacy = True
        ssh_args, env, use_askpass, use_pty_inject = prepare_ssh_invocation(
            host, legacy=legacy, use_keychain=use_keychain, interactive=False
        )
        run_ssh_session(
            ssh_args,
            env,
            use_askpass,
            exec_mode=True,
            host=host,
            use_pty_password_inject=use_pty_inject,
        )

    if legacy:
        return _run_interactive_ssh(host, legacy=True, use_keychain=use_keychain)

    result = _run_interactive_ssh(host, legacy=True, use_keychain=use_keychain)
    if ssh_algorithm_mismatch(result):
        return _run_interactive_ssh(host, legacy=False, use_keychain=use_keychain)
    if legacy_session_viable(result):
        persist_legacy_host(host)
    return result


def apply_keychain_password(host: str, password: str) -> None:
    """Write password to Keychain when set; delete entry when empty."""
    if password:
        keychain_set(host, password)
    else:
        keychain_delete(host)


# ---------------------------------------------------------------------------
# Curses helpers
# ---------------------------------------------------------------------------


def init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)  # selected
    curses.init_pair(2, curses.COLOR_CYAN, -1)  # accent
    curses.init_pair(3, curses.COLOR_YELLOW, -1)  # hint
    curses.init_pair(4, curses.COLOR_RED, -1)  # danger


def char_display_width(char: str) -> int:
    if len(char) != 1:
        return 0
    if unicodedata.east_asian_width(char) in ("F", "W"):
        return 2
    return 1


def str_display_width(text: str) -> int:
    return sum(char_display_width(c) for c in text)


def truncate_display(text: str, max_width: int) -> str:
    if max_width <= 0:
        return ""
    if str_display_width(text) <= max_width:
        return text
    ellipsis = "…"
    ell_w = str_display_width(ellipsis)
    out: List[str] = []
    width = 0
    for char in text:
        char_w = char_display_width(char)
        if width + char_w > max_width - ell_w:
            break
        out.append(char)
        width += char_w
    return "".join(out) + ellipsis


def pad_display(text: str, width: int, align: str = "left") -> str:
    clipped = truncate_display(text, width)
    pad = max(0, width - str_display_width(clipped))
    if align == "right":
        return " " * pad + clipped
    return clipped + " " * pad


def format_conn_flags(conn: Connection) -> str:
    parts: List[str] = []
    if not conn.managed:
        parts.append("ext")
    if conn.has_password:
        parts.append("p")
    if conn.identity_file:
        parts.append("k")
    return " ".join(parts) if parts else "-"


def distribute_column_widths(flex_space: int) -> Tuple[int, int, int]:
    """Split flex space across folder, host, and address with min/max caps."""
    flex_min = COL_FOLDER_MIN + COL_HOST_MIN + COL_ADDR_MIN
    flex_max = COL_FOLDER_MAX + COL_HOST_MAX + COL_ADDR_MAX
    space = max(0, flex_space)

    if space <= flex_min:
        folder_w = COL_FOLDER_MIN
        host_w = COL_HOST_MIN
        addr_w = max(0, space - folder_w - host_w)
        return folder_w, host_w, addr_w

    if space >= flex_max:
        return COL_FOLDER_MAX, COL_HOST_MAX, COL_ADDR_MAX

    ratio = (space - flex_min) / (flex_max - flex_min)
    folder_w = COL_FOLDER_MIN + round(ratio * (COL_FOLDER_MAX - COL_FOLDER_MIN))
    host_w = COL_HOST_MIN + round(ratio * (COL_HOST_MAX - COL_HOST_MIN))
    folder_w = max(COL_FOLDER_MIN, min(COL_FOLDER_MAX, folder_w))
    host_w = max(COL_HOST_MIN, min(COL_HOST_MAX, host_w))
    addr_w = space - folder_w - host_w
    if addr_w > COL_ADDR_MAX:
        addr_w = COL_ADDR_MAX
    elif addr_w < COL_ADDR_MIN:
        addr_w = COL_ADDR_MIN
        overflow = folder_w + host_w + addr_w - space
        if overflow > 0:
            host_cut = min(overflow, host_w - COL_HOST_MIN)
            host_w -= host_cut
            overflow -= host_cut
        if overflow > 0:
            folder_w = max(COL_FOLDER_MIN, folder_w - overflow)
    return folder_w, host_w, addr_w


def table_columns(term_width: int) -> Dict[str, int]:
    usable = max(40, term_width - 2)
    panel_w = min(usable, TABLE_MAX_WIDTH)
    panel_x = 1 + max(0, (usable - panel_w) // 2)

    flags_w = COL_FLAGS_W
    fixed = COL_PREFIX_W + flags_w + TABLE_GAPS
    flex_space = panel_w - fixed
    folder_w, host_w, addr_w = distribute_column_widths(flex_space)
    addr_w = flex_space - folder_w - host_w

    folder_x = panel_x + COL_PREFIX_W
    host_x = folder_x + folder_w + 1
    addr_x = host_x + host_w + 1
    flags_x = panel_x + panel_w - flags_w

    return {
        "margin": panel_x,
        "inner": panel_w,
        "folder_w": folder_w,
        "host_w": host_w,
        "addr_w": addr_w,
        "flags_w": flags_w,
        "folder_x": folder_x,
        "host_x": host_x,
        "addr_x": addr_x,
        "flags_x": flags_x,
    }


def safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x >= width:
        return
    max_len = max(0, width - x - 1)
    win.addstr(y, x, text[:max_len], attr)


def help_key_attr() -> int:
    return curses.A_BOLD


def help_desc_attr() -> int:
    return curses.A_DIM


def focus_attr(focused: bool) -> int:
    return curses.A_BOLD if focused else curses.A_DIM


def safe_addch(win, y: int, x: int, ch, attr: int = 0) -> None:
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x < 0 or x >= width:
        return
    win.addch(y, x, ch, attr)


def help_line_display_width(segments: List[Tuple[str, str]]) -> int:
    if not segments:
        return 0
    sep_w = str_display_width(HELP_SEGMENT_SEP)
    total = 0
    for index, (keys, desc) in enumerate(segments):
        if index:
            total += sep_w
        total += str_display_width(keys) + 1 + str_display_width(desc)
    return total


def help_lines_for_width(width: int) -> List[List[Tuple[str, str]]]:
    inner = max(0, width - 2)
    if help_line_display_width(HELP_HINTS) <= inner:
        return [HELP_HINTS]

    first = HELP_HINTS[:HELP_SPLIT_INDEX]
    second = HELP_HINTS[HELP_SPLIT_INDEX:]
    return [first, second]


def draw_key_desc(
    win,
    row: int,
    x: int,
    key: str,
    desc: str,
    max_display_width: int,
) -> int:
    if max_display_width <= 0:
        return x

    desc_text = f" {desc}"
    desc_w = str_display_width(desc_text)
    key_w = str_display_width(key)
    if key_w + desc_w > max_display_width:
        clip = truncate_display(desc_text, max(0, max_display_width - key_w))
        safe_addstr(win, row, x, key[: max(0, max_display_width)], help_key_attr())
        if clip:
            safe_addstr(win, row, x + len(key), clip, help_desc_attr())
        return x + len(key) + len(clip)

    safe_addstr(win, row, x, key, help_key_attr())
    safe_addstr(win, row, x + len(key), desc_text, help_desc_attr())
    return x + len(key) + len(desc_text)


def draw_help_segments(
    win,
    row: int,
    x: int,
    segments: List[Tuple[str, str]],
    max_display_width: int,
) -> int:
    if max_display_width <= 0:
        return x

    remaining = max_display_width
    sep_w = str_display_width(HELP_SEGMENT_SEP)

    for index, (keys, desc) in enumerate(segments):
        if index:
            if sep_w > remaining:
                break
            safe_addstr(win, row, x, HELP_SEGMENT_SEP, help_desc_attr())
            x += len(HELP_SEGMENT_SEP)
            remaining -= sep_w

        keys_w = str_display_width(keys)
        desc_w = str_display_width(desc) + 1
        segment_w = keys_w + desc_w
        if segment_w > remaining:
            break

        safe_addstr(win, row, x, keys, help_key_attr())
        x += len(keys)
        safe_addstr(win, row, x, " ", help_desc_attr())
        x += 1
        safe_addstr(win, row, x, desc, help_desc_attr())
        x += len(desc)
        remaining -= segment_w

    return x


def draw_box_title(win, title: str) -> None:
    height, width = win.getmaxyx()
    safe_addstr(win, 0, 2, f" {title} ", curses.A_BOLD)
    if width > 4:
        win.hline(0, 1, curses.ACS_HLINE, min(width - 2, max(0, width - 2)))


def getch_utf8(stdscr) -> Tuple[Optional[str], int]:
    """Return (utf8_char or None, key_code)."""
    ch = stdscr.getch()
    if ch == -1:
        return None, ch
    if 0 <= ch <= 255:
        try:
            bytes_seq = bytes([ch])
            # Handle multibyte by reading more if needed for UTF-8
            while ch != -1:
                try:
                    return bytes_seq.decode("utf-8"), ch
                except UnicodeDecodeError:
                    ch2 = stdscr.getch()
                    if ch2 == -1:
                        break
                    if 0 <= ch2 <= 255:
                        bytes_seq += bytes([ch2])
                    else:
                        return None, ch2
        except Exception:
            return None, ch
    return None, ch


def read_line_input(
    stdscr,
    y: int,
    x: int,
    width: int,
    initial: str = "",
    secret: bool = False,
) -> Optional[str]:
    curses.curs_set(1)
    value = list(initial)
    pos = len(value)

    while True:
        display = ("*" * len(value)) if secret else "".join(value)
        safe_addstr(stdscr, y, x, " " * width)
        safe_addstr(stdscr, y, x, display[:width])
        stdscr.move(y, x + min(pos, width - 1))
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (10, 13, curses.KEY_ENTER):
            return "".join(value)
        if ch in (27,):
            return None
        if ch in (3,):
            return None
        if ch in (8, 127, curses.KEY_BACKSPACE):
            if pos > 0:
                value.pop(pos - 1)
                pos -= 1
            continue
        if ch == curses.KEY_DC:
            if pos < len(value):
                value.pop(pos)
            continue
        if ch == curses.KEY_LEFT and pos > 0:
            pos -= 1
            continue
        if ch == curses.KEY_RIGHT and pos < len(value):
            pos += 1
            continue
        if ch == curses.KEY_HOME:
            pos = 0
            continue
        if ch == curses.KEY_END:
            pos = len(value)
            continue
        if 32 <= ch <= 126:
            value.insert(pos, chr(ch))
            pos += 1


# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------

WIZARD_FIELDS_FULL = [
    ("folder", "Category (empty=Uncategorized): ", False),
    ("host", "Name (Host): ", False),
    ("hostname", "Address (IP/domain): ", False),
    ("port", f"Port [{DEFAULT_PORT}]: ", False),
    ("user", "User: ", False),
    ("auth", "Auth [1=password 2=key 3=both]: ", False),
    ("identity_file", "Key path: ", False),
    ("password", "Password (optional): ", True),
]

WIZARD_FIELDS_PASSWORD_ONLY = [
    ("password", "Password (empty=delete): ", True),
]


def wizard_field_visible(key: str, data: WizardData) -> bool:
    if key == "identity_file" and data.auth == AUTH_PASSWORD:
        return False
    if key == "password" and data.auth == AUTH_KEY:
        return False
    return True


def wizard_field_initial(key: str, data: WizardData) -> str:
    if key == "auth":
        return {"password": "1", "key": "2", "both": "3"}.get(data.auth, "1")
    if key == "folder":
        folder = str(getattr(data, "folder", ""))
        return "" if is_uncategorized_folder(folder) else folder
    return str(getattr(data, key, ""))


def apply_wizard_field(key: str, data: WizardData, value: str) -> Optional[str]:
    if key == "host":
        value = value.strip()
        if not value:
            return "Name cannot be empty"
        data.host = value
    elif key == "folder":
        data.folder = value.strip()
    elif key == "hostname":
        data.hostname = value.strip()
        if not data.hostname:
            return "Address cannot be empty"
    elif key == "port":
        data.port = value.strip() or str(DEFAULT_PORT)
    elif key == "user":
        data.user = value.strip()
    elif key == "auth":
        data.auth = {"1": AUTH_PASSWORD, "2": AUTH_KEY, "3": AUTH_BOTH}.get(
            value.strip() or "1", AUTH_PASSWORD
        )
    elif key == "identity_file":
        data.identity_file = value.strip() or DEFAULT_IDENTITY
    elif key == "password":
        data.password = value
    return None


def run_wizard(
    stdscr,
    title: str,
    data: WizardData,
    fields: List[Tuple[str, str, bool]],
) -> Optional[WizardData]:
    height, width = stdscr.getmaxyx()

    for key, label, secret in fields:
        if not wizard_field_visible(key, data):
            continue

        stdscr.clear()
        draw_box_title(stdscr, title)
        safe_addstr(stdscr, 2, 2, label, curses.A_BOLD)
        if key == "auth":
            safe_addstr(stdscr, 3, 4, "1=password  2=key  3=password+key", curses.A_DIM)
        if key == "password" and data.auth != AUTH_KEY:
            hint = "Saved to Keychain; empty removes stored password (enter at connect)"
            safe_addstr(stdscr, 3, 4, hint, curses.A_DIM)

        initial = wizard_field_initial(key, data)
        value = read_line_input(stdscr, 5, 4, width - 8, initial, secret=secret)
        if value is None:
            return None

        error = apply_wizard_field(key, data, value)
        if error:
            safe_addstr(stdscr, 7, 4, error, curses.color_pair(4))
            stdscr.refresh()
            stdscr.getch()
            return None

    if not data.original_host:
        raw = gather_raw_hosts()
        if data.host in raw:
            stdscr.clear()
            draw_box_title(stdscr, title)
            safe_addstr(stdscr, 3, 4, f"Host '{data.host}' already exists", curses.color_pair(4))
            stdscr.refresh()
            stdscr.getch()
            return None

    return data


def wizard_new(stdscr) -> Optional[WizardData]:
    stdscr.clear()
    draw_box_title(stdscr, "New SSH connection")
    data = WizardData()
    result = run_wizard(stdscr, "New SSH connection", data, WIZARD_FIELDS_FULL)
    if result is None:
        return None
    upsert_host_block(result)
    if result.auth in (AUTH_PASSWORD, AUTH_BOTH):
        apply_keychain_password(result.host, result.password)
    else:
        keychain_delete(result.host)
    return result


def wizard_edit(stdscr, conn: Connection) -> Optional[WizardData]:
    stdscr.clear()
    if conn.managed:
        draw_box_title(stdscr, f"Edit {conn.host}")
        data = WizardData(
            host=conn.host,
            folder=conn.folder_display,
            hostname=conn.hostname,
            port=str(conn.port),
            user=conn.user,
            auth=conn.auth,
            identity_file=conn.identity_file or DEFAULT_IDENTITY,
            password=keychain_get(conn.host) or "",
            original_host=conn.host,
        )
        result = run_wizard(stdscr, "Edit", data, WIZARD_FIELDS_FULL)
        if result is None:
            return None
        upsert_host_block(result)
        if result.auth in (AUTH_PASSWORD, AUTH_BOTH):
            apply_keychain_password(result.host, result.password)
        else:
            keychain_delete(result.host)
        return result

    draw_box_title(stdscr, f"Edit {conn.host} [ext]")
    safe_addstr(
        stdscr,
        2,
        2,
        "External config entry: Keychain password only.",
        curses.color_pair(3),
    )
    data = WizardData(
        host=conn.host,
        password=keychain_get(conn.host) or "",
        original_host=conn.host,
    )
    result = run_wizard(stdscr, "Edit password", data, WIZARD_FIELDS_PASSWORD_ONLY)
    if result is None:
        return None
    apply_keychain_password(result.host, result.password)
    return result


def delete_connection(stdscr, conn: Connection) -> bool:
    stdscr.clear()
    draw_box_title(stdscr, "Delete connection")
    confirm_prompt = "Confirm [y/N]"
    lines = [
        f"Delete {conn.host}?",
        "",
        "Will remove:",
    ]
    if conn.managed:
        lines.append("  - Entry in ~/.vnssh/hosts.conf")
    else:
        lines.append("  - (Keeps entry in ~/.ssh/config)")
    if conn.has_password:
        lines.append("  - Keychain password")
    lines.append("  - Usage history")
    lines.append("")
    lines.append(confirm_prompt)

    for i, line in enumerate(lines):
        attr = curses.color_pair(4) if i == 0 and curses.has_colors() else 0
        safe_addstr(stdscr, 2 + i, 2, line, attr)

    confirm_y = 2 + len(lines) - 1
    stdscr.move(confirm_y, 2 + len(confirm_prompt))
    stdscr.refresh()
    while True:
        ch = stdscr.getch()
        if ch in (ord("y"), ord("Y")):
            break
        if ch in (ord("n"), ord("N"), 27, 3, 10, 13):
            return False

    if conn.managed:
        remove_host_block(conn.host, HOSTS_CONF)
    if conn.has_password:
        keychain_delete(conn.host)
    delete_history(conn.host)
    return True


# ---------------------------------------------------------------------------
# Main TUI
# ---------------------------------------------------------------------------


class MainUI:
    """Bottom-input layout: list on top, search box + help at bottom."""

    def __init__(self, stdscr) -> None:
        self.stdscr = stdscr
        self.query = ""
        self.focus = "input"  # input | list
        self.scroll = 0
        self.list_cursor = 0
        self.connections: List[Connection] = []
        self.filtered: List[Connection] = []
        self.message = ""
        self._blink_on = True
        self.reload_connections()

    def layout(self) -> Dict[str, int]:
        height, width = self.stdscr.getmaxyx()
        help_rows = help_lines_for_width(width)
        help_count = len(help_rows)
        help_start = height - help_count
        input_bottom_row = help_start - 1
        input_row = input_bottom_row - 1
        input_top_row = input_row - 1
        status_row = input_top_row - 1
        footer_sep_row = status_row - 1
        header_row = 1
        sep_row = 2
        list_start = 3
        list_end = footer_sep_row - 1
        page_size = max(MIN_PAGE_SIZE, list_end - list_start + 1)
        return {
            "help_rows": list(range(help_start, height)),
            "help_lines": help_rows,
            "input_top_row": input_top_row,
            "input_row": input_row,
            "input_bottom_row": input_bottom_row,
            "status_row": status_row,
            "footer_sep_row": footer_sep_row,
            "header_row": header_row,
            "sep_row": sep_row,
            "list_start": list_start,
            "list_end": list_end,
            "page_size": page_size,
        }

    def reload_connections(self) -> None:
        self.connections = load_connections()
        self.apply_filter(reset_scroll=True)

    def apply_filter(self, reset_scroll: bool = False) -> None:
        self.filtered = sorted_connections(self.connections, self.query)
        if reset_scroll:
            self.scroll = 0
            self.list_cursor = 0
        self.clamp_scroll()

    def clamp_scroll(self) -> None:
        layout = self.layout()
        page_size = layout["page_size"]
        max_scroll = max(0, len(self.filtered) - page_size)
        if self.scroll > max_scroll:
            self.scroll = max_scroll
        visible = self.visible_connections(layout)
        if visible and self.list_cursor >= len(visible):
            self.list_cursor = max(0, len(visible) - 1)
        if not visible:
            self.list_cursor = 0

    def visible_connections(self, layout: Optional[Dict[str, int]] = None) -> List[Connection]:
        if layout is None:
            layout = self.layout()
        end = self.scroll + layout["page_size"]
        return self.filtered[self.scroll : end]

    def selected_connection(self) -> Optional[Connection]:
        visible = self.visible_connections()
        if self.focus != "list" or not visible:
            return None
        if 0 <= self.list_cursor < len(visible):
            return visible[self.list_cursor]
        return None

    def focus_input(self) -> None:
        self.focus = "input"
        self.list_cursor = 0

    def focus_list(self) -> None:
        if not self.filtered:
            return
        self.focus = "list"
        self.clamp_scroll()

    def resume_after_ssh(self) -> None:
        clear_terminal_screen()
        set_terminal_title(VNSSH_TERMINAL_TITLE)
        curses.reset_prog_mode()
        curses.cbreak()
        self.stdscr.keypad(True)
        curses.set_escdelay(25)
        init_colors()
        self.stdscr.clear()
        self.focus_input()
        self.reload_connections()
        self.draw()

    def status_text(self, layout: Dict[str, int]) -> str:
        total = len(self.filtered)
        if total == 0:
            return "0/0"
        start = self.scroll + 1
        visible = self.visible_connections(layout)
        end = self.scroll + len(visible)
        return f"{start}-{end}/{total}"

    def draw_table_header(self, stdscr, width: int) -> None:
        cols = table_columns(width)
        attr = curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        safe_addstr(stdscr, 1, cols["margin"], " " * COL_PREFIX_W, attr)
        safe_addstr(
            stdscr,
            1,
            cols["folder_x"],
            pad_display("Category", cols["folder_w"]),
            attr,
        )
        safe_addstr(
            stdscr,
            1,
            cols["host_x"],
            pad_display("Name", cols["host_w"]),
            attr,
        )
        safe_addstr(
            stdscr,
            1,
            cols["addr_x"],
            pad_display("Address", cols["addr_w"]),
            attr,
        )
        safe_addstr(
            stdscr,
            1,
            cols["flags_x"],
            pad_display("Flags", cols["flags_w"], "right"),
            attr,
        )

    def draw_connection_row(
        self, stdscr, row: int, width: int, conn: Connection, selected: bool
    ) -> None:
        cols = table_columns(width)
        item_attr = curses.color_pair(1) if selected and curses.has_colors() else (
            curses.A_REVERSE if selected else 0
        )
        prefix = "> " if selected else "  "
        safe_addstr(stdscr, row, cols["margin"], prefix, item_attr)
        safe_addstr(
            stdscr,
            row,
            cols["folder_x"],
            pad_display(conn.folder_display, cols["folder_w"]),
            item_attr,
        )
        safe_addstr(
            stdscr,
            row,
            cols["host_x"],
            pad_display(conn.host, cols["host_w"]),
            item_attr,
        )
        safe_addstr(
            stdscr,
            row,
            cols["addr_x"],
            pad_display(conn.label, cols["addr_w"]),
            item_attr,
        )
        safe_addstr(
            stdscr,
            row,
            cols["flags_x"],
            pad_display(format_conn_flags(conn), cols["flags_w"], "right"),
            item_attr,
        )

    def draw_input_box(self, stdscr, layout: Dict[str, int], width: int) -> None:
        top_row = layout["input_top_row"]
        row = layout["input_row"]
        bottom_row = layout["input_bottom_row"]
        cols = table_columns(width)
        left = cols["margin"]
        right = cols["margin"] + cols["inner"] - 1
        hline_len = max(0, right - left - 1)
        border_attr = curses.A_DIM
        focused = self.focus == "input"

        if right > left + 1:
            safe_addch(stdscr, top_row, left, curses.ACS_ULCORNER, border_attr)
            if hline_len:
                stdscr.hline(top_row, left + 1, curses.ACS_HLINE, hline_len, border_attr)
            safe_addch(stdscr, top_row, right, curses.ACS_URCORNER, border_attr)

            safe_addch(stdscr, row, left, curses.ACS_VLINE, border_attr)

            safe_addch(stdscr, bottom_row, left, curses.ACS_LLCORNER, border_attr)
            if hline_len:
                stdscr.hline(bottom_row, left + 1, curses.ACS_HLINE, hline_len, border_attr)
            safe_addch(stdscr, bottom_row, right, curses.ACS_LRCORNER, border_attr)

        content_x = left + 2
        content_w = max(0, right - content_x)
        safe_addstr(stdscr, row, content_x, SEARCH_PREFIX, focus_attr(focused))
        x = content_x + len(SEARCH_PREFIX)
        max_query = max(0, content_w - len(SEARCH_PREFIX))
        if self.query:
            safe_addstr(
                stdscr,
                row,
                x,
                self.query[:max_query],
                focus_attr(focused),
            )
            x += min(len(self.query), max_query)
        if focused and self._blink_on and x < right:
            safe_addstr(stdscr, row, x, " ", curses.A_REVERSE)
        elif not self.query and not focused and x < right:
            safe_addstr(stdscr, row, x, " ", help_desc_attr())

        if right > left + 1:
            safe_addch(stdscr, row, right, curses.ACS_VLINE, border_attr)

    def draw_status_bar(self, stdscr, layout: Dict[str, int], width: int) -> None:
        row = layout["status_row"]
        cols = table_columns(width)
        status = self.status_text(layout)
        status_attr = curses.A_DIM
        status_x = cols["margin"] + cols["inner"] - len(status)
        safe_addstr(stdscr, row, status_x, status, status_attr)

        if self.message:
            max_left = max(0, status_x - cols["margin"] - 1)
            safe_addstr(
                stdscr,
                row,
                cols["margin"],
                self.message[:max_left],
                curses.color_pair(3),
            )

    def draw_help_lines(self, stdscr, layout: Dict[str, int], width: int) -> None:
        cols = table_columns(width)
        for row, segments in zip(layout["help_rows"], layout["help_lines"]):
            draw_help_segments(stdscr, row, cols["margin"], segments, cols["inner"])

    def draw_panel_rule(self, stdscr, row: int, width: int) -> None:
        cols = table_columns(width)
        safe_addstr(
            stdscr,
            row,
            cols["margin"],
            ("-" * cols["inner"])[: cols["inner"]],
            curses.A_DIM,
        )

    def draw_footer(self, stdscr, layout: Dict[str, int], width: int) -> None:
        self.draw_panel_rule(stdscr, layout["footer_sep_row"], width)
        self.draw_status_bar(stdscr, layout, width)
        self.draw_input_box(stdscr, layout, width)
        self.draw_help_lines(stdscr, layout, width)

    def draw(self) -> None:
        stdscr = self.stdscr
        stdscr.clear()
        _height, width = stdscr.getmaxyx()
        layout = self.layout()
        draw_box_title(stdscr, "vnssh")
        curses.curs_set(0)

        self.draw_table_header(stdscr, width)
        self.draw_panel_rule(stdscr, layout["sep_row"], width)

        visible = self.visible_connections(layout)
        for idx, conn in enumerate(visible):
            row = layout["list_start"] + idx
            if row > layout["list_end"]:
                break
            selected = self.focus == "list" and idx == self.list_cursor
            self.draw_connection_row(stdscr, row, width, conn, selected)

        self.draw_footer(stdscr, layout, width)

        stdscr.refresh()

    def page_scroll(self, direction: int) -> None:
        layout = self.layout()
        step = layout["page_size"]
        max_scroll = max(0, len(self.filtered) - step)
        self.scroll = max(0, min(self.scroll + direction * step, max_scroll))
        self.clamp_scroll()

    def move_list(self, delta: int) -> None:
        if not self.filtered:
            self.focus_input()
            return

        layout = self.layout()
        visible = self.visible_connections(layout)
        if not visible:
            return

        if delta < 0:
            if self.list_cursor > 0:
                self.list_cursor -= 1
            elif self.scroll > 0:
                self.scroll -= 1
            else:
                self.focus_input()
            return

        if self.list_cursor < len(visible) - 1:
            self.list_cursor += 1
        elif self.scroll + self.list_cursor < len(self.filtered) - 1:
            self.scroll += 1
        else:
            self.focus_input()

    def connect_selected(self, conn: Connection) -> None:
        self.message = ""
        curses.def_prog_mode()
        curses.endwin()
        prepare_terminal_for_shell()
        result = connect_host(conn.host, exec_mode=False)
        self.resume_after_ssh()
        if should_report_connect_error(result):
            self.message = format_connect_error(conn.host, result)
            self.draw()

    def open_new_wizard(self) -> None:
        wizard_new(self.stdscr)
        self.reload_connections()

    def handle_input_key(self, ch: int, char: Optional[str]) -> Optional[str]:
        if ch not in (-1,):
            self.message = ""
        if ch in (8, 127, curses.KEY_BACKSPACE):
            self.query = self.query[:-1]
            self.apply_filter(reset_scroll=True)
            return None
        if ch == 27:
            if self.query:
                self.query = ""
                self.apply_filter(reset_scroll=True)
                return None
            return "quit"
        if ch in (curses.KEY_UP,):
            self.focus_list()
            return None
        if ch in (curses.KEY_DOWN,):
            return None
        if ch in (curses.KEY_PPAGE, 2):  # PgUp, Ctrl-B
            self.page_scroll(-1)
            return None
        if ch in (curses.KEY_NPAGE, 6):  # PgDn, Ctrl-F
            self.page_scroll(1)
            return None
        if ch == KEY_CTRL_N:
            return "new"
        if ch in (10, 13, curses.KEY_ENTER):
            if len(self.filtered) == 1:
                return "connect_one"
            if self.filtered:
                self.focus_list()
            return None
        if char and char.isprintable() and len(char) == 1:
            self.query += char
            self.apply_filter(reset_scroll=True)
            return None
        return None

    def handle_list_key(self, ch: int, char: Optional[str]) -> Optional[str]:
        if ch not in (-1,):
            self.message = ""
        if ch in (curses.KEY_UP,):
            self.move_list(-1)
            return None
        if ch in (curses.KEY_DOWN,):
            self.move_list(1)
            return None
        if ch in (curses.KEY_PPAGE, 2):  # PgUp, Ctrl-B
            self.page_scroll(-1)
            return None
        if ch in (curses.KEY_NPAGE, 6):  # PgDn, Ctrl-F
            self.page_scroll(1)
            return None
        if ch == 27:
            self.focus_input()
            return None
        if ch == KEY_CTRL_N:
            return "new"
        if ch in (ord("e"), ord("E")):
            return "edit"
        if ch in (ord("d"), ord("D")):
            return "delete"
        if ch in (10, 13, curses.KEY_ENTER):
            return "connect"
        if char and char.isprintable() and len(char) == 1:
            self.focus_input()
            self.query += char
            self.apply_filter(reset_scroll=True)
            return None
        return None

    def run(self) -> None:
        ensure_include()
        while True:
            self.draw()
            if self.focus == "input":
                self.stdscr.timeout(SEARCH_CURSOR_BLINK_MS)
            else:
                self.stdscr.timeout(-1)

            char, ch = getch_utf8(self.stdscr)

            if ch == -1 and self.focus == "input":
                self._blink_on = not self._blink_on
                continue

            action: Optional[str] = None
            if self.focus == "input":
                action = self.handle_input_key(ch, char)
                if action == "quit":
                    break
            else:
                action = self.handle_list_key(ch, char)

            if action is None:
                continue
            if action == "new":
                self.message = ""
                self.open_new_wizard()
            elif action == "connect_one":
                self.message = ""
                self.connect_selected(self.filtered[0])
            elif action == "connect":
                conn = self.selected_connection()
                if conn:
                    self.message = ""
                    self.connect_selected(conn)
            elif action == "edit":
                conn = self.selected_connection()
                if conn:
                    self.message = ""
                    wizard_edit(self.stdscr, conn)
                    self.reload_connections()
                else:
                    self.message = "Select a connection to edit"
            elif action == "delete":
                conn = self.selected_connection()
                if conn:
                    self.message = ""
                    if delete_connection(self.stdscr, conn):
                        self.reload_connections()
                else:
                    self.message = "Select a connection to delete"


def main_curses(stdscr) -> None:
    set_terminal_title(VNSSH_TERMINAL_TITLE)
    curses.set_escdelay(25)
    init_colors()
    stdscr.keypad(True)
    curses.cbreak()
    stdscr.nodelay(False)
    height, width = stdscr.getmaxyx()
    if height < MIN_TERMINAL_HEIGHT or width < 40:
        raise SystemExit("Terminal too small; enlarge the window and retry.")
    pending_session_archives = find_pending_session_archive_weeks()
    try:
        MainUI(stdscr).run()
    finally:
        archive_pending_session_weeks(pending_session_archives)


def import_template_path() -> Path:
    return Path.cwd() / IMPORT_TEMPLATE_FILENAME


def write_import_template(path: Path) -> bool:
    """Write a sample CSV import template; return False if path already exists."""
    if path.exists():
        return False
    rows = [
        {
            "category": "Production",
            "host": "prod-web",
            "hostname": "203.0.113.10",
            "user": "alice",
            "port": "22",
            "password": "",
            "identity_file": "",
            "auth": "password",
        },
        {
            "category": "Development",
            "host": "dev-app",
            "hostname": "10.0.0.5",
            "user": "deploy",
            "port": "22",
            "password": "",
            "identity_file": "~/.ssh/id_ed25519",
            "auth": "key",
        },
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=IMPORT_TEMPLATE_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    return True


def cmd_init() -> None:
    if is_vnssh_initialized():
        print(f"Already initialized: {HOSTS_CONF} and {SSH_CONFIG}")
    else:
        ensure_include()
        print(f"Initialized {VNSSH_DIR}")
        print(f"Ensured {SSH_CONFIG} includes: {INCLUDE_MARKER}")
    template = import_template_path()
    if write_import_template(template):
        print(f"Wrote import template: {template}")
    else:
        print(f"Import template already exists: {template}")


def cmd_list() -> None:
    ensure_include()
    for conn in sorted_connections(load_connections(), ""):
        badges = conn.badges
        print(f"{conn.folder_display}\t{conn.host}\t{conn.label}\t{badges}")


def cmd_connect(host: str) -> None:
    ensure_include()
    connect_host(host, exec_mode=True)


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------


def normalize_import_header(name: str) -> Optional[str]:
    key = name.strip().lower().replace(" ", "_")
    for canonical, aliases in IMPORT_COLUMNS.items():
        if key == canonical or key in aliases:
            return canonical
    return None


def canonicalize_import_row(raw: Dict[str, str]) -> Dict[str, str]:
    row: Dict[str, str] = {}
    for key, value in raw.items():
        if key is None:
            continue
        canonical = normalize_import_header(key)
        if canonical and value is not None:
            row[canonical] = value.strip()
    return row


def parse_import_auth(value: str, identity_file: str, password: str) -> str:
    token = value.strip().lower()
    if token in ("", "password", "pass", "1"):
        return AUTH_PASSWORD
    if token in ("key", "2"):
        return AUTH_KEY
    if token in ("both", "3"):
        return AUTH_BOTH
    if identity_file and password:
        return AUTH_BOTH
    if identity_file:
        return AUTH_KEY
    return AUTH_PASSWORD


def row_to_wizard(row: Dict[str, str]) -> WizardData:
    host = row.get("host", "").strip()
    hostname = row.get("hostname", "").strip()
    user = row.get("user", "").strip()
    if not host:
        raise ValueError("missing host (connection name)")
    if not hostname:
        raise ValueError(f"{host}: missing hostname (address)")
    if not user:
        raise ValueError(f"{host}: missing user")

    port = row.get("port", "").strip() or str(DEFAULT_PORT)
    password = row.get("password", "")
    identity_file = row.get("identity_file", "").strip()
    auth = parse_import_auth(row.get("auth", ""), identity_file, password)

    return WizardData(
        host=host,
        folder=row.get("category", "").strip(),
        hostname=hostname,
        user=user,
        port=port,
        auth=auth,
        identity_file=identity_file or DEFAULT_IDENTITY,
        password=password,
    )


def host_is_managed(host: str) -> bool:
    raw = gather_raw_hosts()
    entry = raw.get(host)
    if not entry:
        return False
    return entry[1].resolve() == HOSTS_CONF.resolve()


def host_exists(host: str) -> bool:
    return host in gather_raw_hosts()


def plan_import_action(data: WizardData, force: bool = False) -> str:
    if host_exists(data.host):
        if host_is_managed(data.host):
            return "update_managed" if force else "skip_managed"
        return "keychain_ext" if data.password else "skip_ext"
    return "add"


def import_wizard_data(data: WizardData, force: bool = False, dry_run: bool = False) -> str:
    """Import one row. Returns action label for reporting."""
    action = plan_import_action(data, force=force)
    if dry_run:
        return action

    if action == "skip_managed" or action == "skip_ext":
        return action

    if action == "update_managed":
        data.original_host = data.host
        upsert_host_block(data)
        if data.auth in (AUTH_PASSWORD, AUTH_BOTH):
            apply_keychain_password(data.host, data.password)
        else:
            keychain_delete(data.host)
        return action

    if action == "keychain_ext":
        apply_keychain_password(data.host, data.password)
        return action

    upsert_host_block(data)
    if data.auth in (AUTH_PASSWORD, AUTH_BOTH):
        apply_keychain_password(data.host, data.password)
    else:
        keychain_delete(data.host)
    return "add"


def dedupe_config_entries(
    entries: List[Tuple[str, Dict[str, str], str]],
) -> List[Tuple[str, Dict[str, str], str]]:
    """Keep the last occurrence of each Host alias."""
    seen: set[str] = set()
    deduped_reversed: List[Tuple[str, Dict[str, str], str]] = []
    for host, opts, folder in reversed(entries):
        if host in seen:
            continue
        seen.add(host)
        deduped_reversed.append((host, opts, folder))
    deduped_reversed.reverse()
    return deduped_reversed


def rebuild_hosts_from_csv(rows: List[WizardData]) -> None:
    """Rebuild managed hosts.conf from CSV, preserving per-host opts when present."""
    existing = {
        host: (opts, folder)
        for host, opts, folder in parse_config_entries(read_config_text(HOSTS_CONF))
    }
    csv_hosts = {data.host for data in rows}
    entries: List[Tuple[str, Dict[str, str], str]] = []

    for data in rows:
        prior_opts = existing.get(data.host, ({}, FOLDER_UNCATEGORIZED))[0]
        entries.append(
            (
                data.host,
                merged_opts_from_wizard(data, prior_opts or None),
                normalize_folder(data.folder),
            )
        )

    for host, (opts, folder) in existing.items():
        if host not in csv_hosts:
            entries.append((host, opts, folder))

    write_hosts_conf(dedupe_config_entries(entries))


def read_import_csv(path: Path) -> List[WizardData]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV is missing a header row")

        rows: List[WizardData] = []
        for line_no, raw in enumerate(reader, start=2):
            if not any((value or "").strip() for value in raw.values()):
                continue
            canonical = canonicalize_import_row(raw)
            try:
                rows.append(row_to_wizard(canonical))
            except ValueError as exc:
                raise ValueError(f"Line {line_no}: {exc}") from exc
        return rows


def cmd_import(argv: List[str]) -> None:
    force = "--force" in argv
    dry_run = "--dry-run" in argv
    paths = [arg for arg in argv if not arg.startswith("--")]

    if len(paths) != 1:
        print(
            "Usage: vnssh import [--dry-run] [--force] <file.csv>\n"
            "\n"
            "CSV headers:\n"
            "  category, host, hostname, user, port, password, identity_file, auth\n"
            "\n"
            f"Run `vnssh init` to create {IMPORT_TEMPLATE_FILENAME} in the current directory.\n"
            "\n"
            "Rules:\n"
            "  - New Host -> write ~/.vnssh/hosts.conf + Keychain\n"
            "  - Existing in ~/.ssh/config [ext] -> import password to Keychain only\n"
            "  - Existing in hosts.conf -> skip by default; --force overwrites config and password\n"
            "\n"
            "auth values: password / key / both (or 1 / 2 / 3)"
        )
        sys.exit(1)

    csv_path = Path(paths[0]).expanduser()
    if not csv_path.exists():
        print(f"File not found: {csv_path}")
        sys.exit(1)

    ensure_include()
    rows = read_import_csv(csv_path)

    stats = {
        "add": 0,
        "update_managed": 0,
        "keychain_ext": 0,
        "skip_managed": 0,
        "skip_ext": 0,
    }

    prefix = "[dry-run] " if dry_run else ""

    if force and not dry_run:
        rebuild_hosts_from_csv(rows)
        for data in rows:
            if data.auth in (AUTH_PASSWORD, AUTH_BOTH):
                apply_keychain_password(data.host, data.password)
            else:
                keychain_delete(data.host)
            stats["update_managed"] += 1
            print(f"{prefix}Updated {data.host}")
    else:
        for data in rows:
            action = import_wizard_data(data, force=force, dry_run=dry_run)

            stats[action] = stats.get(action, 0) + 1

            if action == "add":
                print(f"{prefix}Added {data.host} -> {data.user}@{data.hostname}")
            elif action == "update_managed":
                print(f"{prefix}Updated {data.host}")
            elif action == "keychain_ext":
                print(f"{prefix}Keychain only [ext] {data.host}")
            elif action == "skip_managed":
                print(
                    f"{prefix}Skipped (exists in hosts.conf): {data.host} "
                    f"(use --force to overwrite)"
                )
            elif action == "skip_ext":
                print(f"{prefix}Skipped [ext] {data.host} (no password column)")

    print(
        f"\n{prefix}Done: added {stats['add']}, "
        f"updated {stats['update_managed']}, "
        f"Keychain [ext] {stats['keychain_ext']}, "
        f"skipped {stats['skip_managed'] + stats['skip_ext']}"
    )


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------


def main() -> None:
    if is_askpass_mode() or "--askpass" in sys.argv:
        askpass_main()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "init":
            cmd_init()
            return
        if cmd == "list":
            cmd_list()
            return
        if cmd == "connect" and len(sys.argv) > 2:
            cmd_connect(sys.argv[2])
            return
        if cmd == "import":
            cmd_import(sys.argv[2:])
            return
        print(
            "Usage: vnssh | vnssh init | vnssh list | vnssh connect <Host> | "
            "vnssh import [--dry-run] [--force] <file.csv>"
        )
        sys.exit(1)

    curses.wrapper(main_curses)


# ---------------------------------------------------------------------------
# Embedded pinyin LUT (GB2312 level-1 hanzi, gzip+base64, single-file)
# ---------------------------------------------------------------------------

_PINYIN_GZ_B64 = (
    "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"
    "msoG9/P2i//v/wM2ZCZvv7EAAA=="
)


if __name__ == "__main__":
    main()