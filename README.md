# vnssh

Terminal SSH launcher for macOS. Distributed as a single `vnssh.py` file; uses the system Python 3 and OpenSSH only—no third-party packages.

[中文文档](README.zh-CN.md)

## Features

### TUI

vnssh presents a full-screen TUI host list with live filtering. As you type in the search box, the list narrows immediately and sorts by relevance (exact `Host` alias first, then prefix and substring matches, then recent-use history).

Search spans **Category**, **Host alias**, **HostName**, **User**, **Port**, and the combined address label. Matching is case-insensitive substring search over those fields. Host names and categories that contain **CJK characters** also get a built-in romanization index, so an ASCII query can match labels you do not have an input method for (e.g. matching initials or syllables of a Chinese category name).

With an empty search box, hosts are sorted by recent connections.

### Keychain passwords

Password credentials are not stored in `hosts.conf`, `~/.ssh/config`, or `vnssh.py`. vnssh writes them to the macOS Keychain via the `security` CLI: service name (`svce`) `vnssh`, account name (`acct`) equal to each `Host` alias.

- **Separation of config and secrets**: config files can be backed up or version-controlled without plaintext passwords.
- **OS-managed storage**: secrets live in Keychain under macOS access controls; vnssh reads them on demand with `security find-generic-password` only when connecting—no hardcoded passwords and no password content in session logs.
- **Replaceable client**: `vnssh.py` is just the caller; upgrading or removing the script does not delete Keychain entries. Redeploy and reuse the same `Host` names (macOS may prompt for Keychain access again).

The TUI marks hosts with a stored password as **p**. Key-only hosts do not create Keychain password items.

### OpenSSH integration

vnssh does not implement a private SSH protocol. Connections and on-disk config follow OpenSSH conventions:

- **Connections**: launched through the system `ssh` binary with the same effective arguments you would use manually.
- **Config**: managed hosts live in `~/.vnssh/hosts.conf` (standard `Host`, `HostName`, `User`, `Port`, `IdentityFile`, etc.). On first run, vnssh only prepends `Include ~/.vnssh/hosts.conf` to `~/.ssh/config`; existing `Host` blocks are left unchanged.
- **Works without vnssh**: if you remove vnssh but keep `hosts.conf` and the `Include` line, `ssh <Host>` still works. Password hosts need your own input method (Keychain integration is provided by vnssh).

Entries in `~/.ssh/config` that vnssh does not manage appear in the TUI marked **ext**.

### Legacy protocol auto-compatibility

Some older switches and appliances only offer weaker algorithms (`ssh-rsa`, `diffie-hellman-group1-sha1`, `3des-cbc`, etc.). Modern OpenSSH defaults may fail negotiation with errors such as:

- `no matching key exchange method found`
- `no matching cipher found`
- `no matching mac found`
- `no matching host key type found`

vnssh handles this in two ways:

1. **Auto-learn**: on first failure with matching stderr, vnssh adds `#v-legacy` above the `Host` block and, on the next attempt, applies compatible `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs`, etc., persisted in `hosts.conf`.
2. **Manual tag**: add `#v-legacy` up front to skip the initial failure.

For `#v-legacy` hosts whose `HostName` is a plain IP, vnssh also adds a `Host <IP>` alias stanza in `hosts.conf` so `ssh user@<IP>` picks up the same legacy options as `ssh <Host-alias>`.

### Session logs

After **login completes**, each SSH session’s remote terminal output is written under `~/.vnssh/sessions/`:

- **One file per session**: separate `.session` files named with host, endpoint, and timestamp.
- **No auth capture**: password prompts and OTP challenges are excluded.
- **Incremental flush**: post-login output is flushed to disk during the session; most content survives abnormal disconnects.
- **Automatic archival**: when you quit the TUI, sessions from completed calendar weeks (Monday–Sunday, local time) before the current week are packed into `YYYY-MM-DD_YYYY-MM-DD.tar.gz`, source `.session` files are deleted on success, and processed weeks are recorded in `.archive-state.json`—no manual steps.

Environment toggles (see `session_logging_enabled()` / `session_archive_enabled()` in `vnssh.py`):

| Variable | Default | Effect |
|----------|---------|--------|
| `VNSSH_SESSION_LOG` | on | Set to `0`, `false`, `no`, or `off` to disable session recording |
| `VNSSH_SESSION_ARCHIVE` | on | Set to `0`, `false`, `no`, or `off` to disable weekly packing on TUI exit |

Examples: `VNSSH_SESSION_LOG=0 vnssh` or `VNSSH_SESSION_ARCHIVE=0 vnssh`.

### CSV import

For bulk onboarding or migration:

```bash
vnssh init                              # write vnssh-hosts-template.csv (idempotent)
vnssh import hosts.csv                  # import
vnssh import --dry-run hosts.csv        # preview only
vnssh import --force hosts.csv          # overwrite existing managed Host entries
```

`vnssh init` skips setup when `hosts.conf` and the `Include` line already exist; it does not overwrite an existing template in the current directory.

| Column | Description |
|--------|-------------|
| `category` | Written as `#v-f:` comment; maps to TUI Category |
| `host` | `Host` alias (required) |
| `hostname` | Address (required) |
| `user` | Username (required) |
| `port` | Port (default `22`) |
| `password` | If non-empty, stored in Keychain—not in config files |
| `identity_file` | Private key path |
| `auth` | `password`, `key`, or `both` (also `1`, `2`, `3`) |

Import rules:

| Situation | Behavior |
|-----------|----------|
| New Host | Write `hosts.conf`; store password in Keychain when provided |
| Already in `hosts.conf` | Skip by default; `--force` updates config and Keychain |
| Already in `~/.ssh/config` (ext) | Config unchanged; password column updates Keychain only |

Common header aliases are accepted (e.g. `folder` → `category`). Run `--dry-run` first to verify the action summary.

## Requirements

- macOS
- Python 3
- OpenSSH (`ssh`)
- Terminal at least 16 rows × 40 columns

## Quick start

```bash
chmod +x vnssh.py
cp vnssh.py ~/.local/bin/vnssh    # optional: on PATH as vnssh
./vnssh.py                         # or simply: vnssh
```

Ensure `~/.local/bin` is on your `PATH` (zsh example in `~/.zshrc`: `export PATH="$HOME/.local/bin:$PATH"`).

First run creates `~/.vnssh/`, `hosts.conf`, and the `Include` line in `~/.ssh/config` if missing. **No separate `init` is required** for daily use.

### Add a host

1. Run `vnssh`
2. Press **Ctrl-N** to create a host
3. Enter category, name, address, user, and auth; optional password goes to Keychain
4. Select the host and press **Enter** to connect

## Configuration

Paths vnssh uses:

| Path | Contents |
|------|----------|
| `~/.vnssh/hosts.conf` | Managed `Host` definitions (OpenSSH format) |
| `~/.ssh/config` | Your existing SSH config; vnssh only adds `Include ~/.vnssh/hosts.conf` |
| `~/Library/Keychains/` | Keychain items for service `vnssh` |
| `~/.vnssh/sessions/` | Session logs (`.session`) and archives (`.tar.gz`) |
| `~/.vnssh/history.json` | Connection frequency (for sort order) |

Optional comment lines **above** a `Host` block (all optional):

| Comment | If omitted | If present |
|---------|------------|------------|
| `#v-f:Name` | TUI Category shows **Uncategorized** | Shows the given category; included in search |
| `#v-2fa` | With a Keychain password, uses normal `SSH_ASKPASS` injection; otherwise manual entry | Interactive connects use PTY prompt detection for password inject; OTP typed in the SSH terminal |
| `#v-legacy` | OpenSSH default algorithms; auto-learned on negotiation failure | Legacy algorithm set applied immediately |

Example (any of the three comments may be omitted):

```sshconfig
#v-f:Production
#v-2fa
Host bastion-example
    HostName 203.0.113.10
    User alice
    Port 8321
```

## TUI shortcuts

| Key | Action |
|-----|--------|
| Enter | Connect |
| Ctrl-N | New host |
| e | Edit |
| d | Delete |
| ↑ / ↓ | Move selection |
| PgUp / PgDn | Page list |
| Ctrl-B / Ctrl-F | Page list (same as PgUp / PgDn) |
| Esc | Clear search; quit when search is empty |

Badges: **p** = password in Keychain, **k** = SSH key configured, **ext** = external SSH config.

## CLI

```bash
vnssh list
vnssh connect <Host>
vnssh import hosts.csv
vnssh import --dry-run file.csv
vnssh init
```

For day-to-day browsing, search, and connect, the TUI is usually easier. The CLI is better for scripts, bulk import, or a quick non-interactive connect to one host.

## Security

**Keychain**

- Passwords are Generic Password items in the login keychain: `svce=vnssh`, `acct=<Host-alias>`.
- vnssh accesses them only through `/usr/bin/security`; neither the script nor `hosts.conf` contains plaintext password fields.
- Other users or processes must pass macOS security policy; first access may show an authorization dialog.
- Delete one host’s entry manually: `security delete-generic-password -s vnssh -a <Host>` (vnssh also removes entries when you edit or delete a host).

**Configuration files**

- `hosts.conf` may expose internal hostnames, users, and ports but not passwords; treat backups as sensitive metadata.
- Removing the `Include` line disables vnssh-managed hosts without touching the rest of `~/.ssh/config`.

**Session logs**

- Logs start after authentication but may still contain commands and application output; restrict filesystem permissions under `~/.vnssh/sessions/`.
- Weekly archives are unencrypted `tar.gz` files; handle retention accordingly.
- Disable logging entirely with `VNSSH_SESSION_LOG=0`.

## Troubleshooting

**Terminal too small**

- The TUI requires at least 16 rows × 40 columns (`MIN_TERMINAL_HEIGHT`). Enlarge the window and restart.

**Authentication failed / Permission denied**

- Press **e** and verify `User`, `HostName`, port, and `auth` mode.
- Key auth: confirm `IdentityFile` exists and key permissions are tight (typically mode `600`).
- Password auth: check Keychain Access for service `vnssh` and the matching `Host` account; no **p** badge means no Keychain entry.
- Manual check (prints the password—safe environments only): `security find-generic-password -s vnssh -a <Host> -w`.

**2FA / bastion issues**

- Ensure `#v-2fa` is above the `Host` block and Keychain has a password for the **Host alias** (not the IP).
- Without `#v-2fa`, PTY password injection is not used; multi-step verification may fail.
- Enter OTP in the SSH terminal vnssh opens; logging starts only after auth, so OTP is not written to session files.

**Legacy protocol / algorithm mismatch**

- On first `no matching cipher` (or similar) error, connect again; vnssh should persist `#v-legacy`.
- If it still fails, add `#v-legacy` manually above the `Host` line.
- Compare with `ssh -v <Host>` to confirm legacy options apply (`Include` must be readable by OpenSSH).

**Empty session log / `tail -f` shows nothing**

- Files are created only after login completes; nothing is logged during authentication.
- Only remote output is recorded, not local keystrokes.
- Archival runs only when **exiting the TUI**; `vnssh connect` and other CLI subcommands do not trigger packing.

**CSV import skipped rows**

- Existing managed hosts are skipped unless you pass `--force`.
- External (`ext`) hosts are never rewritten in config; a `password` column updates Keychain only.

## License

[MIT](LICENSE)