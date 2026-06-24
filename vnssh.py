#!/usr/bin/env python3
"""vnssh - macOS SSH launcher with search, favorites, and Keychain passwords."""

from __future__ import annotations

import curses
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

VNSSH_DIR = Path.home() / ".vnssh"
HOSTS_CONF = VNSSH_DIR / "hosts.conf"
HISTORY_FILE = VNSSH_DIR / "history.json"
SSH_CONFIG = Path.home() / ".ssh" / "config"
KEYCHAIN_SERVICE = "vnssh"
INCLUDE_MARKER = "Include ~/.vnssh/hosts.conf"
DEFAULT_PORT = 22
DEFAULT_IDENTITY = "~/.ssh/id_ed25519"
LIST_SLOTS = 8

AUTH_PASSWORD = "password"
AUTH_KEY = "key"
AUTH_BOTH = "both"

AUTH_LABELS = {
    AUTH_PASSWORD: "密码登录",
    AUTH_KEY: "SSH 密钥",
    AUTH_BOTH: "密码 + 密钥",
}


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

    @property
    def label(self) -> str:
        addr = self.hostname or "?"
        user = self.user or "?"
        suffix = f":{self.port}" if self.port != DEFAULT_PORT else ""
        return f"{user}@{addr}{suffix}"

    @property
    def badges(self) -> str:
        parts: List[str] = []
        if not self.managed:
            parts.append("[ext]")
        if self.has_password:
            parts.append("🔑")
        if self.identity_file:
            parts.append("🔐")
        return " ".join(parts)


@dataclass
class WizardData:
    host: str = ""
    hostname: str = ""
    port: str = str(DEFAULT_PORT)
    user: str = ""
    auth: str = AUTH_PASSWORD
    identity_file: str = DEFAULT_IDENTITY
    password: str = ""
    save_password: bool = True
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
    keychain_delete(account)
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
        raise RuntimeError(proc.stderr.strip() or "无法写入 Keychain")


def keychain_delete(account: str) -> None:
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


def keychain_has(account: str) -> bool:
    return keychain_get(account) is not None


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


def parse_host_blocks(text: str) -> List[Tuple[str, Dict[str, str]]]:
    """Return list of (host_pattern, options dict) in file order."""
    blocks: List[Tuple[str, Dict[str, str]]] = []
    current_hosts: List[str] = []
    current_opts: Dict[str, str] = {}
    in_match = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("match "):
            if current_hosts and not in_match:
                for h in current_hosts:
                    blocks.append((h, dict(current_opts)))
            current_hosts = []
            current_opts = {}
            in_match = True
            continue
        if in_match:
            continue
        if lower.startswith("host "):
            if current_hosts:
                for h in current_hosts:
                    blocks.append((h, dict(current_opts)))
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
        for h in current_hosts:
            blocks.append((h, dict(current_opts)))

    return blocks


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


def gather_raw_hosts() -> Dict[str, Tuple[Dict[str, str], Path]]:
    """Map host alias -> (options from first defining block, source file)."""
    seen: Dict[str, Tuple[Dict[str, str], Path]] = {}
    visited: set[Path] = set()

    def walk(path: Path) -> None:
        path = path.resolve()
        if path in visited:
            return
        visited.add(path)
        text = read_config_text(path)
        for host_name, opts in parse_host_blocks(text):
            if is_listable_host(host_name) and host_name not in seen:
                seen[host_name] = (opts, path)
        for include_path in collect_includes(text, path.parent):
            walk(include_path)

    if SSH_CONFIG.exists():
        walk(SSH_CONFIG)
    if HOSTS_CONF.exists():
        walk(HOSTS_CONF)
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


def infer_auth(opts: Dict[str, str], has_password: bool) -> str:
    identity = opts.get("identityfile", "")
    if identity and has_password:
        return AUTH_BOTH
    if identity:
        return AUTH_KEY
    return AUTH_PASSWORD


def load_connections() -> List[Connection]:
    raw = gather_raw_hosts()
    connections: List[Connection] = []
    managed_path = HOSTS_CONF.resolve()

    for host, (opts, source) in raw.items():
        resolved = resolve_with_ssh_g(host)
        hostname = resolved.get("hostname") or opts.get("hostname", "")
        user = resolved.get("user") or opts.get("user", "")
        port_str = resolved.get("port") or opts.get("port", str(DEFAULT_PORT))
        try:
            port = int(port_str)
        except ValueError:
            port = DEFAULT_PORT
        # Only explicit config IdentityFile counts; ssh -G lists system defaults.
        identity = opts.get("identityfile")
        has_pw = keychain_has(host)
        auth = infer_auth({"identityfile": identity or ""}, has_pw)
        connections.append(
            Connection(
                host=host,
                hostname=hostname,
                user=user,
                port=port,
                identity_file=identity,
                auth=auth,
                managed=source.resolve() == managed_path,
                has_password=has_pw,
            )
        )

    return connections


def ensure_vnssh_dir() -> None:
    VNSSH_DIR.mkdir(parents=True, exist_ok=True)
    if not HOSTS_CONF.exists():
        HOSTS_CONF.write_text(
            "# Managed by vnssh\n",
            encoding="utf-8",
        )


def ensure_include() -> None:
    ensure_vnssh_dir()
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
    lines = [f"Host {data.host}", f"    HostName {data.hostname}"]
    if data.user:
        lines.append(f"    User {data.user}")
    port = data.port.strip() or str(DEFAULT_PORT)
    if port != str(DEFAULT_PORT):
        lines.append(f"    Port {port}")
    if data.auth in (AUTH_KEY, AUTH_BOTH):
        identity = data.identity_file.strip() or DEFAULT_IDENTITY
        lines.append(f"    IdentityFile {identity}")
    return "\n".join(lines) + "\n"


def remove_host_block(host: str, path: Path = HOSTS_CONF) -> bool:
    text = read_config_text(path)
    if not text:
        return False
    pattern = re.compile(
        rf"^Host\s+{re.escape(host)}\s*$.*?(?=^Host\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    new_text, count = pattern.subn("", text)
    if count == 0:
        return False
    new_text = re.sub(r"\n{3,}", "\n\n", new_text).strip()
    if new_text:
        new_text += "\n"
    path.write_text(new_text, encoding="utf-8")
    return True


def upsert_host_block(data: WizardData) -> None:
    ensure_vnssh_dir()
    if data.original_host and data.original_host != data.host:
        remove_host_block(data.original_host, HOSTS_CONF)
        if keychain_has(data.original_host):
            pw = keychain_get(data.original_host)
            if pw:
                keychain_set(data.host, pw)
            keychain_delete(data.original_host)
        rename_history(data.original_host, data.host)
    elif data.original_host:
        remove_host_block(data.original_host, HOSTS_CONF)

    block = format_host_block(data)
    existing = read_config_text(HOSTS_CONF)
    if existing and not existing.endswith("\n"):
        existing += "\n"
    HOSTS_CONF.write_text(existing + block, encoding="utf-8")


# ---------------------------------------------------------------------------
# Search, sort, filter
# ---------------------------------------------------------------------------


def connection_matches(conn: Connection, query: str) -> bool:
    if not query:
        return True
    q = query.lower()
    fields = [
        conn.host,
        conn.hostname,
        conn.user,
        str(conn.port),
        conn.label,
    ]
    return any(q in f.lower() for f in fields if f)


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
    return (4, -history_score(conn.host))


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
    """Absolute path used as SSH_ASKPASS (OpenSSH execs this directly)."""
    return str(Path(sys.argv[0]).resolve())


def is_askpass_mode() -> bool:
    # OpenSSH runs SSH_ASKPASS without extra args; VNSSH_HOST marks askpass calls.
    return bool(os.environ.get("VNSSH_HOST"))


def askpass_main() -> None:
    host = os.environ.get("VNSSH_HOST", "")
    if not host:
        sys.exit(1)
    password = keychain_get(host)
    if password is None:
        sys.exit(1)
    sys.stdout.write(password)
    sys.stdout.flush()
    sys.exit(0)


def connection_auth_mode(host: str) -> str:
    raw = gather_raw_hosts()
    entry = raw.get(host)
    opts = entry[0] if entry else {}
    has_identity = bool(opts.get("identityfile"))
    has_pw = keychain_has(host)
    return infer_auth({"identityfile": opts.get("identityfile", "")}, has_pw)


def build_ssh_argv(host: str) -> List[str]:
    args = ["ssh"]
    mode = connection_auth_mode(host)
    if mode == AUTH_PASSWORD and keychain_has(host):
        args.extend(
            [
                "-o",
                "PreferredAuthentications=password",
                "-o",
                "PubkeyAuthentication=no",
            ]
        )
    args.append(host)
    return args


def connect_host(host: str, use_keychain: bool = True) -> None:
    record_use(host)
    ssh_args = build_ssh_argv(host)
    env = os.environ.copy()
    if use_keychain and keychain_has(host):
        env["VNSSH_HOST"] = host
        env["SSH_ASKPASS"] = askpass_program()
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = env.get("DISPLAY", ":0")
        os.execvpe("ssh", ssh_args, env)
    os.execvp("ssh", ssh_args)


def apply_password_changes(host: str, password: str, save: bool) -> None:
    if save and password:
        keychain_set(host, password)
    elif not save:
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


def safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x >= width:
        return
    max_len = max(0, width - x - 1)
    win.addstr(y, x, text[:max_len], attr)


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
    ("host", "名字 (Host): ", False),
    ("hostname", "地址 (IP/域名): ", False),
    ("port", f"端口 [{DEFAULT_PORT}]: ", False),
    ("user", "帐号 (User): ", False),
    ("auth", "认证方式 [1密码 2密钥 3两者]: ", False),
    ("identity_file", "密钥路径: ", False),
    ("password", "登录密码 (可留空): ", True),
    ("save_password", "保存密码到 Keychain [Y/n]: ", False),
]

WIZARD_FIELDS_PASSWORD_ONLY = [
    ("password", "登录密码 (留空删除): ", True),
    ("save_password", "保存到 Keychain [Y/n]: ", False),
]


def wizard_field_visible(key: str, data: WizardData) -> bool:
    if key == "identity_file" and data.auth == AUTH_PASSWORD:
        return False
    if key == "password" and data.auth == AUTH_KEY:
        return False
    if key == "save_password" and data.auth == AUTH_KEY:
        return False
    # 密码留空时不保存 Keychain，无需再问
    if key == "save_password" and not data.password:
        return False
    return True


def wizard_field_initial(key: str, data: WizardData) -> str:
    if key == "save_password":
        return "Y" if data.save_password else "n"
    if key == "auth":
        return {"password": "1", "key": "2", "both": "3"}.get(data.auth, "1")
    return str(getattr(data, key, ""))


def apply_wizard_field(key: str, data: WizardData, value: str) -> Optional[str]:
    if key == "host":
        value = value.strip()
        if not value:
            return "名字不能为空"
        data.host = value
    elif key == "hostname":
        data.hostname = value.strip()
        if not data.hostname:
            return "地址不能为空"
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
    elif key == "save_password":
        data.save_password = value.strip().lower() not in ("n", "no")
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
            safe_addstr(stdscr, 3, 4, "1=密码  2=密钥  3=密码+密钥", curses.A_DIM)
        if key == "password" and data.auth != AUTH_KEY:
            hint = "留空则连接时手动输入，不写入 Keychain"
            if data.original_host and keychain_has(data.original_host):
                hint = "留空则删除 Keychain 密码，连接时手动输入"
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
            safe_addstr(stdscr, 3, 4, f"Host '{data.host}' 已存在", curses.color_pair(4))
            stdscr.refresh()
            stdscr.getch()
            return None

    return data


def wizard_new(stdscr) -> Optional[WizardData]:
    stdscr.clear()
    draw_box_title(stdscr, "新建 SSH 连接")
    data = WizardData()
    result = run_wizard(stdscr, "新建 SSH 连接", data, WIZARD_FIELDS_FULL)
    if result is None:
        return None
    upsert_host_block(result)
    if result.auth in (AUTH_PASSWORD, AUTH_BOTH):
        if result.password and result.save_password:
            keychain_set(result.host, result.password)
        elif not result.password:
            keychain_delete(result.host)
    else:
        keychain_delete(result.host)
    return result


def wizard_edit(stdscr, conn: Connection) -> Optional[WizardData]:
    stdscr.clear()
    if conn.managed:
        draw_box_title(stdscr, f"编辑 {conn.host}")
        data = WizardData(
            host=conn.host,
            hostname=conn.hostname,
            port=str(conn.port),
            user=conn.user,
            auth=conn.auth,
            identity_file=conn.identity_file or DEFAULT_IDENTITY,
            password=keychain_get(conn.host) or "",
            save_password=conn.has_password,
            original_host=conn.host,
        )
        result = run_wizard(stdscr, "编辑", data, WIZARD_FIELDS_FULL)
        if result is None:
            return None
        upsert_host_block(result)
        if result.auth in (AUTH_PASSWORD, AUTH_BOTH):
            if result.password and result.save_password:
                keychain_set(result.host, result.password)
            elif not result.password:
                keychain_delete(result.host)
        else:
            keychain_delete(result.host)
        return result

    draw_box_title(stdscr, f"编辑 {conn.host} [ext]")
    safe_addstr(stdscr, 2, 2, "外部 config 条目：仅可修改 Keychain 密码。", curses.color_pair(3))
    data = WizardData(
        host=conn.host,
        password=keychain_get(conn.host) or "",
        save_password=conn.has_password,
        original_host=conn.host,
    )
    result = run_wizard(stdscr, "编辑密码", data, WIZARD_FIELDS_PASSWORD_ONLY)
    if result is None:
        return None
    if result.password and result.save_password:
        keychain_set(result.host, result.password)
    else:
        keychain_delete(result.host)
    return result


def delete_connection(stdscr, conn: Connection) -> bool:
    stdscr.clear()
    draw_box_title(stdscr, "删除连接")
    lines = [
        f"删除 {conn.host} ?",
        "",
        "将删除:",
    ]
    if conn.managed:
        lines.append("  - ~/.vnssh/hosts.conf 中的配置")
    else:
        lines.append("  - (保留 ~/.ssh/config 中的配置)")
    if conn.has_password:
        lines.append("  - Keychain 密码")
    lines.append("  - 使用记录")
    lines.append("")
    lines.append("确认 [y/N]")

    for i, line in enumerate(lines):
        attr = curses.color_pair(4) if i == 0 and curses.has_colors() else 0
        safe_addstr(stdscr, 2 + i, 2, line, attr)

    confirm_y = 2 + len(lines) - 1
    stdscr.move(confirm_y, 2 + len("确认 [y/N]"))
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
    def __init__(self, stdscr) -> None:
        self.stdscr = stdscr
        self.query = ""
        self.focus_search = True
        self.cursor = 0
        self.connections: List[Connection] = []
        self.filtered: List[Connection] = []
        self.message = ""
        self.reload()

    def reload(self) -> None:
        self.connections = load_connections()
        self.filtered = sorted_connections(self.connections, self.query)
        max_cursor = min(LIST_SLOTS, len(self.filtered))
        if self.cursor > max_cursor:
            self.cursor = max_cursor

    def menu_items(self) -> List[Optional[Connection]]:
        items: List[Optional[Connection]] = [None]
        for conn in self.filtered[:LIST_SLOTS]:
            items.append(conn)
        return items

    def draw(self) -> None:
        stdscr = self.stdscr
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        draw_box_title(stdscr, "vnssh")

        search_label = "🔍 "
        search_text = self.query
        if self.focus_search and curses.curs_set:
            curses.curs_set(1)
        else:
            curses.curs_set(0)

        attr = curses.color_pair(1) if self.focus_search and curses.has_colors() else (
            curses.A_REVERSE if self.focus_search else 0
        )
        line = f"{search_label}{search_text}"
        safe_addstr(stdscr, 2, 2, line.ljust(max(0, width - 4))[: max(0, width - 4)], attr)
        if self.focus_search:
            cursor_x = 2 + len(search_label) + len(search_text)
            if cursor_x < width - 1:
                stdscr.move(2, cursor_x)

        safe_addstr(stdscr, 3, 2, "-" * max(0, width - 4))

        items = self.menu_items()
        row = 4
        for idx, item in enumerate(items):
            selected = not self.focus_search and self.cursor == idx
            prefix = "▶ " if selected else "  "
            if item is None:
                text = "新建 SSH 连接"
            else:
                badges = f" {item.badges}" if item.badges else ""
                text = f"{item.host:<16} {item.label}{badges}"
            item_attr = curses.color_pair(1) if selected and curses.has_colors() else (
                curses.A_REVERSE if selected else 0
            )
            safe_addstr(stdscr, row, 2, f"{prefix}{text}"[: max(0, width - 4)], item_attr)
            row += 1

        help_y = max(row + 1, height - 3)
        help_text = "输入:搜索  ↑↓:移动  Enter:确认  e:编辑  d:删除  Esc:清空/退出"
        safe_addstr(stdscr, help_y, 2, help_text[: max(0, width - 4)], curses.A_DIM)
        if self.message:
            safe_addstr(stdscr, help_y + 1, 2, self.message[: max(0, width - 4)], curses.color_pair(3))

        stdscr.refresh()

    def handle_search_key(self, ch: int, char: Optional[str]) -> bool:
        if ch in (8, 127, curses.KEY_BACKSPACE):
            self.query = self.query[:-1]
            self.reload()
            return True
        if ch == 27:
            if self.query:
                self.query = ""
                self.reload()
                return True
            return False
        if ch in (curses.KEY_DOWN, 9):
            self.focus_search = False
            self.cursor = 0
            return True
        if char and char.isprintable() and len(char) == 1:
            self.query += char
            self.reload()
            return True
        return True

    def handle_menu_key(self, ch: int, char: Optional[str]) -> Optional[str]:
        items = self.menu_items()
        max_idx = len(items) - 1

        if ch in (curses.KEY_UP,):
            if self.cursor == 0:
                self.focus_search = True
            else:
                self.cursor -= 1
            return None
        if ch in (curses.KEY_DOWN,):
            if self.cursor < max_idx:
                self.cursor += 1
            return None
        if ch == 27:
            self.focus_search = True
            return None
        if ch in (ord("e"), ord("E")):
            return "edit"
        if ch in (ord("d"), ord("D")):
            return "delete"
        if ch in (10, 13, curses.KEY_ENTER):
            return "activate"
        return None

    def run(self) -> None:
        ensure_include()
        while True:
            self.message = ""
            self.draw()
            char, ch = getch_utf8(self.stdscr)

            if self.focus_search:
                if not self.handle_search_key(ch, char):
                    break
                continue

            action = self.handle_menu_key(ch, char)
            if action is None:
                continue

            items = self.menu_items()
            selected = items[self.cursor] if self.cursor < len(items) else None

            if action == "activate":
                if selected is None:
                    wizard_new(self.stdscr)
                    self.reload()
                else:
                    curses.endwin()
                    connect_host(selected.host)
                    return
            elif action == "edit":
                if selected is None:
                    self.message = "请选择一条连接再编辑"
                else:
                    wizard_edit(self.stdscr, selected)
                    self.reload()
            elif action == "delete":
                if selected is None:
                    self.message = "请选择一条连接再删除"
                else:
                    if delete_connection(self.stdscr, selected):
                        self.reload()


def main_curses(stdscr) -> None:
    curses.set_escdelay(25)
    init_colors()
    stdscr.keypad(True)
    curses.cbreak()
    stdscr.nodelay(False)
    height, width = stdscr.getmaxyx()
    if height < 14 or width < 40:
        raise SystemExit("终端窗口太小，请放大后重试。")
    MainUI(stdscr).run()


def cmd_init() -> None:
    ensure_include()
    print(f"已初始化 {VNSSH_DIR}")
    print(f"已确保 {SSH_CONFIG} 包含: {INCLUDE_MARKER}")


def cmd_list() -> None:
    ensure_include()
    for conn in sorted_connections(load_connections(), ""):
        badges = conn.badges
        print(f"{conn.host}\t{conn.label}\t{badges}")


def cmd_connect(host: str) -> None:
    ensure_include()
    connect_host(host)


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
        print("用法: vnssh | vnssh init | vnssh list | vnssh connect <Host>")
        sys.exit(1)

    curses.wrapper(main_curses)


if __name__ == "__main__":
    main()