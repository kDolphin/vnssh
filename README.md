# vnssh

Terminal SSH launcher for macOS with **Keychain password storage** and **session operation logs**. Distributed as a single `vnssh.py` file; uses the system Python 3 and OpenSSH only—no third-party packages.

Current version: **1.0.7** (`vnssh --version`).

[中文文档](README.zh-CN.md)

## Quick start

**Requirements:** macOS · Python 3 · OpenSSH (`ssh`) · terminal at least 16 rows × 40 columns

```bash
chmod +x vnssh.py
cp vnssh.py ~/.local/bin/vnssh    # optional: on PATH as vnssh
./vnssh.py                         # or simply: vnssh
```

Ensure `~/.local/bin` is on your `PATH` (zsh example in `~/.zshrc`: `export PATH="$HOME/.local/bin:$PATH"`).

First run creates `~/.vnssh/`, `hosts.conf`, and the `Include` line in `~/.ssh/config` if missing. **No separate `init` is required** for daily use.

### Add a host

1. Run `vnssh` (title bar shows the version)
2. Press **Ctrl-N** to create a host
3. Enter category, name, address, user, and auth (Unicode/CJK is fine for category and name); optional password goes to Keychain. Use **Up** to go back a field; a validation error stays on that field. For a bastion/OTP host, set **2FA / bastion** to `y` (writes `#v-2fa`). For old network gear, set **Legacy SSH algorithms** to `y` (writes `#v-legacy`). When editing, leave **Password** empty to keep the current Keychain secret; type `-` to delete it.
4. Select the host and press **Enter** to connect. While connecting, **Ctrl-C** cancels and returns to the host list. Network errors and authentication failures also return to the list instead of leaving the terminal stuck.

### CLI cheat sheet

```bash
vnssh list
vnssh connect <Host>
vnssh --version
```

More commands: [CLI](#cli).

## Features

### TUI

vnssh presents a full-screen TUI host list with live filtering. As you type in the search box, the list narrows immediately and sorts by relevance (exact `Host` alias first, then prefix and substring matches, then recent-use history). The title bar shows `vnssh <version>`.

Search spans **Category**, **Host alias**, **HostName**, **User**, **Port**, and the combined address label. Matching is case-insensitive substring search over those fields. Host names and categories that contain **CJK characters** also get a built-in romanization index, so an ASCII query can match labels you do not have an input method for (e.g. matching initials or syllables of a Chinese category name).

With an empty search box, hosts are sorted by recent connections.

New/edit wizards (Ctrl-N / **e**) accept **UTF-8 input**, including Chinese and other CJK text, in fields such as **Category** and **Name**. **Enter** advances, **Up** returns to the previous field, **Esc** cancels; invalid input is shown on the same field instead of aborting the whole form. Password and both-auth hosts include a **2FA / bastion** (`y`/`n`) field that writes or removes `#v-2fa`. Every managed host also has **Legacy SSH algorithms** (`y`/`n`) for `#v-legacy`. After a connect returns (success, error, or cancel), the TUI keeps that host selected.

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

### Connect, cancel, and errors

TUI and `vnssh connect <Host>` run OpenSSH on a PTY and always try to return when the attempt ends—success, failure, or cancel—rather than leaving a frozen SSH screen. The TUI then restores the list with that host still selected.

- **Cancel**: before a remote shell is up, **Ctrl-C** stops the local `ssh` process and returns to the TUI. After login, Ctrl-C is forwarded to the remote session as usual.
- **Auth / extra prompts**: on a second Keychain/askpass prompt (OTP, retry, etc.), **Ctrl-C** or **Esc** cancels instead of sitting in a line buffer.
- **Hard failures**: messages such as connection timed out, connection refused, no route to host, network unreachable, permission denied, or authentication failed (including common Chinese phrases such as 密码错误 / 认证失败) end the attempt and show a status-bar error.
- **Watchdog**: if nothing is happening and you are not being asked to type (password, OTP, or host-key `yes/no`), the pre-login attempt is stopped after about **20 seconds**. OpenSSH `ConnectTimeout` remains **5 seconds** for the TCP handshake. Waiting for you to type does not consume that 20-second budget.

A line `Connecting... (Ctrl-C to cancel)` is printed at the start of each attempt.

### Legacy protocol auto-compatibility

Some older switches and appliances only offer weaker algorithms (`ssh-rsa`, `diffie-hellman-group1-sha1`, `3des-cbc`, etc.). Modern OpenSSH defaults may fail negotiation with errors such as:

- `no matching key exchange method found`
- `no matching cipher found`
- `no matching mac found`
- `no matching host key type found`

Untagged hosts connect with OpenSSH defaults first. Only a negotiation mismatch retries with the legacy algorithm set.

vnssh handles this in two ways:

1. **Auto-learn**: if the default attempt fails with matching stderr, vnssh retries immediately with compatible `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs`, etc., then writes `#v-legacy` above the `Host` block for next time.
2. **Manual tag**: in the wizard set **Legacy SSH algorithms** to `y`, or add `#v-legacy` above the `Host` block, to skip the default attempt.

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

### CSV import and export

For bulk onboarding, backup, or migration:

```bash
vnssh init                              # write vnssh-hosts-template.csv (idempotent)
vnssh import hosts.csv                  # import
vnssh import --dry-run hosts.csv        # preview only
vnssh import --force hosts.csv          # overwrite existing managed Host entries
vnssh export                            # write vnssh-hosts.csv (no passwords)
vnssh export backup.csv                 # choose a path
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
| `twofa` | `y` / `n` (optional; writes `#v-2fa`) |
| `legacy` | `y` / `n` (optional; writes `#v-legacy`) |

Import rules:

| Situation | Behavior |
|-----------|----------|
| New Host | Write `hosts.conf`; store a password only when that column has a value |
| Already in `hosts.conf` | Skip by default; `--force` rewrites that Host block only. No password column leaves Keychain unchanged |
| Already in `~/.ssh/config` (ext) | Not copied into `hosts.conf`; a password cell updates Keychain, empty or `-` deletes it |

Common header aliases are accepted (e.g. `folder` → `category`). Run `--dry-run` first to verify the action summary.

`vnssh export` writes the same columns **except `password`**. Re-importing that file, including with `--force`, restores host config and `#v-2fa` / `#v-legacy` and does not delete Keychain entries just because the password column is absent. An empty password or `-` deletes the entry.

## Configuration

Paths vnssh uses:

| Path | Contents |
|------|----------|
| `~/.vnssh/hosts.conf` | Managed `Host` definitions (OpenSSH format) |
| `~/.ssh/config` | Your existing SSH config; vnssh only adds `Include ~/.vnssh/hosts.conf` |
| `~/Library/Keychains/` | Keychain items for service `vnssh` |
| `~/.vnssh/sessions/` | Session logs (`.session`) and archives (`.tar.gz`) |
| `~/.vnssh/history.json` | Connection frequency (for sort order) |
| `~/.vnssh/.keychain-accounts.json` | Cache of Keychain *account names* (not passwords) so the TUI can start without dumping the whole keychain |

Optional comment lines **above** a `Host` block (all optional):

| Comment | If omitted | If present |
|---------|------------|------------|
| `#v-f:Name` | TUI Category shows **Uncategorized** | Shows the given category; included in search |
| `#v-2fa` | With a Keychain password, uses normal `SSH_ASKPASS` injection; otherwise manual entry | Interactive connects use PTY prompt detection for password inject; OTP typed in the SSH terminal. Set from the wizard **2FA / bastion** field (`y`) |
| `#v-legacy` | OpenSSH default algorithms; auto-learned on negotiation failure | Legacy algorithm set applied immediately. Set from the wizard **Legacy SSH algorithms** field (`y`) |

Example (any of the three comments may be omitted):

```sshconfig
#v-f:Production
#v-2fa
Host bastion-example
    HostName 203.0.113.10
    User alice
    Port 8321
```

Category comments may use CJK, for example `#v-f:生产环境`.

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
| Ctrl-C | While connecting (before a remote shell): cancel and return to the list |

Badges: **p** = password in Keychain, **k** = SSH key configured, **ext** = external SSH config, **2** = 2FA/bastion (`#v-2fa`), **L** = legacy algorithms (`#v-legacy`).

## CLI

```bash
vnssh                         # open TUI
vnssh list
vnssh connect <Host>
vnssh import hosts.csv
vnssh import --dry-run file.csv
vnssh export
vnssh export backup.csv
vnssh init
vnssh version                 # print version
vnssh --version               # same
vnssh -V                      # same
```

| Command | Description |
|---------|-------------|
| *(no args)* | Launch the full-screen TUI |
| `list` | Print hosts (non-interactive) |
| `connect <Host>` | Connect to one host (same PTY relay as the TUI: Ctrl-C, hard-fail, 20s watchdog) |
| `import [options] <file.csv>` | Bulk import; supports `--dry-run` and `--force` |
| `export [file.csv]` | Write hosts to CSV with no password column (default `vnssh-hosts.csv`) |
| `init` | Ensure setup and write the CSV template |
| `version` / `--version` / `-V` | Print `vnssh <version>` and exit |

For day-to-day browsing, search, and connect, the TUI is usually easier. The CLI is better for scripts, bulk import/export, version checks, or a quick connect to one host.

## Security

**Keychain**

- Passwords are Generic Password items in the login keychain: `svce=vnssh`, `acct=<Host-alias>`.
- vnssh accesses them only through `/usr/bin/security`; neither the script nor `hosts.conf` contains plaintext password fields. The TUI editor never prefills a stored password; leave the field empty to keep it, or type `-` to delete it.
- Account *names* (not secrets) may be cached in `~/.vnssh/.keychain-accounts.json` so startup can skip a full keychain dump.
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

**Stuck on connect / cannot return to the TUI**

- Press **Ctrl-C** while the `Connecting...` line is showing (before a remote shell). That aborts local `ssh` and redraws the list.
- Network failures and auth errors should return automatically; the reason appears on the status bar.
- If a host is waiting for OTP or `yes/no`, type the response or Ctrl-C to cancel. After login, Ctrl-C goes to the remote process, not vnssh.

**Authentication failed / Permission denied**

- You should land back on the host list with a status-bar error (not a stuck password prompt).
- Press **e** and verify `User`, `HostName`, port, and `auth` mode.
- Key auth: confirm `IdentityFile` exists. OpenSSH requires private-key mode `600`; keys in Dropbox/iCloud are often reset to `644` after a Mac restart, which yields `Permission denied`. vnssh runs `chmod 600` before connect; you can also `chmod 600 <key>` or keep keys under `~/.ssh/`.
- Password auth: check Keychain Access for service `vnssh` and the matching `Host` account; no **p** badge means no Keychain entry. Editing a host: empty password keeps the current secret; `-` deletes it.
- Manual check (prints the password—safe environments only): `security find-generic-password -s vnssh -a <Host> -w`.

**2FA / bastion issues**

- Edit the host and set **2FA / bastion** to `y`, or put `#v-2fa` above the `Host` block. Keychain must have a password for the **Host alias** (not the IP).
- Without `#v-2fa`, PTY password injection is not used; multi-step verification may fail.
- Enter OTP in the SSH terminal vnssh opens; logging starts only after auth, so OTP is not written to session files.

**Legacy protocol / algorithm mismatch**

- Untagged hosts try OpenSSH defaults first; a negotiation mismatch retries with legacy algorithms and then writes `#v-legacy`.
- To skip the default attempt, edit the host and set **Legacy SSH algorithms** to `y`, or add `#v-legacy` above the `Host` line.
- Compare with `ssh -v <Host>` to confirm legacy options apply (`Include` must be readable by OpenSSH).

**Empty session log / `tail -f` shows nothing**

- Files are created only after login completes; nothing is logged during authentication.
- Only remote output is recorded, not local keystrokes.
- Archival runs only when **exiting the TUI**; `vnssh connect` and other CLI subcommands do not trigger packing.

**CSV import skipped rows**

- Existing managed hosts are skipped unless you pass `--force`.
- External (`ext`) hosts are never rewritten in config; a `password` column updates Keychain only.
- `vnssh export` omits passwords; re-import restores config and `twofa` / `legacy` flags only.

## License

[MIT](LICENSE)
