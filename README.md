# vnssh

macOS SSH launcher with a terminal UI, Keychain-backed passwords, 2FA bastion support, and optional session logging. Single-file distribution (`vnssh.py`), no third-party dependencies.

[中文文档](README.zh-CN.md)

## Features

- **TUI host list** — search by name, address, or folder (pinyin initials supported)
- **Keychain passwords** — credentials stay out of config files
- **OpenSSH integration** — manages `Include ~/.vnssh/hosts.conf` in `~/.ssh/config`
- **2FA / bastion hosts** — auto-fill password via PTY; enter OTP in the terminal (`#v-2fa`)
- **Legacy devices** — auto-learns `#v-legacy` after algorithm mismatch (or set it upfront)
- **Session logs** — post-login terminal output under `~/.vnssh/sessions/` (nested bastion targets get separate files)
- **CSV import** — bulk-add hosts from a spreadsheet

## Requirements

- macOS
- Python 3
- OpenSSH (`ssh`)
- Terminal at least 16 rows × 40 columns

## Quick start

```bash
chmod +x vnssh.py
./vnssh.py
```

No separate `init` step is required. On first run, vnssh automatically:

1. Creates `~/.vnssh/` and `hosts.conf`
2. Prepends `Include ~/.vnssh/hosts.conf` to `~/.ssh/config` if missing

### Add your first host

1. Run `vnssh`
2. Press **Ctrl-N** to open the new-host wizard
3. Fill in name, address, user, and auth; optional password is stored in Keychain (service `vnssh`)
4. Select the host and press **Enter** to connect

## TUI shortcuts

| Key | Action |
|-----|--------|
| Enter | Connect |
| Ctrl-N | New host |
| e | Edit |
| d | Delete |
| ↑ / ↓ | Move selection |
| PgUp / PgDn | Page list |
| Esc | Clear search / quit |

Badges: **p** = password in Keychain, **k** = SSH key configured, **ext** = host from external SSH config.

## CLI

```bash
vnssh list
vnssh connect <Host>
vnssh import hosts.csv
vnssh import --dry-run hosts.csv
vnssh init          # optional; same as first-run setup, prints confirmation
```

## Configuration

Hosts live in `~/.vnssh/hosts.conf` (OpenSSH format). Optional comment lines above a `Host` block:

| Comment | Purpose |
|---------|---------|
| `#v-f:Name` | Folder / category in the TUI |
| `#v-2fa` | Keyboard-interactive 2FA (PTY password inject + manual OTP) |
| `#v-legacy` | Legacy SSH algorithms (optional; auto-detected on first failure) |

Example:

```sshconfig
#v-f:Production
#v-2fa
Host bastion-example
    HostName 203.0.113.10
    User alice
    Port 8321
```

## Session logging

- Enabled by default; files under `~/.vnssh/sessions/`
- Logs terminal output **after** login (not OTP/password prompts)
- Tencent Cloud bastion: a separate log file is created per nested target login, e.g. `2026-06-25_120000_10.0.0.1_user_via_bastion-example.session`
- Disable: `VNSSH_SESSION_LOG=0 vnssh`

## CSV import

Use English column headers: `host`, `hostname`, `user`, `port`, `password`, `folder`, `auth`.

`auth`: `password`, `key`, or `both` (also `1`, `2`, `3`).

## Security

- Passwords are stored only in the macOS Keychain, not in `hosts.conf` or the script
- Session logs may contain commands and output; restrict access to `~/.vnssh/`
- macOS may prompt for Keychain access the first time passwords are saved

## Troubleshooting

**Terminal too small** — resize the window and retry.

**Authentication failed** — verify credentials; press **e** to edit; check Keychain service `vnssh`.

**2FA host stuck** — ensure `#v-2fa` is set and the host name has a Keychain entry.

**Legacy device fails once** — reconnect; vnssh should persist `#v-legacy` automatically.

## License

[MIT](LICENSE)