# vnssh

macOS 终端 SSH 启动器，支持 **Keychain 密码存储** 与 **会话操作日志**。单文件 `vnssh.py` 分发，依赖系统 Python 3 与 OpenSSH，无第三方包。

当前版本：**1.0.8**（`vnssh --version`）。

[English](README.md)

## 快速开始

**环境要求：** macOS · Python 3 · OpenSSH（`ssh`） · 终端至少 16 行 × 40 列

```bash
chmod +x vnssh.py
cp vnssh.py ~/.local/bin/vnssh    # 可选：加入 PATH，命令名 vnssh
./vnssh.py                         # 或直接：vnssh
```

确保 `~/.local/bin` 在 `PATH` 中（zsh 可在 `~/.zshrc` 添加 `export PATH="$HOME/.local/bin:$PATH"`）。

首次运行自动创建 `~/.vnssh/`、`hosts.conf`，并在 `~/.ssh/config` 加入 `Include`（已存在则跳过）。**无需单独执行 `init`**。

### 添加主机

1. 运行 `vnssh`（标题栏显示版本号）
2. **Ctrl-N** 新建
3. 填写 category、名称、地址、用户、认证（category / 名称支持中文）；密码可选，存入 Keychain。**Up** 回到上一栏；校验失败停在当前栏。堡垒机/OTP 主机把 **2FA / bastion** 填 `y`（写入 `#v-2fa`）。旧交换机把 **Legacy SSH algorithms** 填 `y`（写入 `#v-legacy`）。编辑时 **Password** 留空表示保留 Keychain 里的原密码，输入 `-` 删除。
4. 选中主机，**Enter** 连接。连接过程中 **Ctrl-C** 可取消并回到主机列表；网络错误、密码/认证失败也会回到列表，而不会把终端卡在 SSH 画面里。

### 命令行速查

```bash
vnssh list
vnssh connect <Host名>
vnssh --version
```

完整命令见 [命令行](#命令行)。

## 功能

### TUI 界面

vnssh 以全屏 TUI 展示主机列表，支持实时过滤。搜索框输入任意片段后，列表即时收窄并按相关度排序（精确匹配 Host 别名优先，其次前缀与子串匹配，再结合最近使用记录）。标题栏显示 `vnssh <版本号>`。

可搜索字段包括：**Category**、**Host 别名**、**HostName**、**User**、**Port** 及组合标签。中文主机名与 Category 额外建立拼音索引，支持**全拼**与**首字母**匹配（例如 Category「生产环境」可用 `sc`、`schj` 等片段命中）。

未输入搜索词时，列表按最近连接记录排序。

新建 / 编辑向导（Ctrl-N / **e**）的输入框支持 **UTF-8**，**Category**、**Name** 等字段可直接输入中文及其他 CJK 字符。**Enter** 下一栏，**Up** 上一栏，**Esc** 取消；填错只留在当前栏，不会整单作废。密码 / 密码+密钥主机有 **2FA / bastion**（`y`/`n`）一栏，用于写入或去掉 `#v-2fa`。托管主机另有 **Legacy SSH algorithms**（`y`/`n`）对应 `#v-legacy`。连接返回后（成功、失败或取消），列表仍停在刚才那台主机。

### Keychain 密码

密码类凭据不写入 `hosts.conf`、`~/.ssh/config` 或 `vnssh.py`，而是通过 macOS `security` 命令存入系统钥匙串：服务名（`svce`）为 `vnssh`，账户名（`acct`）对应各 `Host` 别名。

- **配置与凭据分离**：配置文件可备份或纳入版本管理，其中不含明文密码。
- **系统级存储**：凭据由 Keychain 管理，读取受 macOS 访问控制约束；vnssh 仅在连接时按需调用 `security find-generic-password`，不在脚本内硬编码、不将密码写入日志文件。
- **程序可替换**：`vnssh.py` 仅为调用方；更换或删除脚本不影响 Keychain 已有条目，重新部署后同名 `Host` 可继续取用（系统可能再次弹出 Keychain 授权）。

TUI 列表以 **p** 标记 Keychain 中已有密码的主机。纯密钥认证主机不创建密码条目。

### OpenSSH 集成

vnssh 不实现私有 SSH 协议，连接与配置均遵循 OpenSSH 标准：

- **连接**：通过系统 `ssh` 发起，参数与手工执行一致。
- **配置**：托管主机写在 `~/.vnssh/hosts.conf`（标准 `Host` / `HostName` / `User` / `Port` / `IdentityFile` 等）。首次运行仅在 `~/.ssh/config` 顶部加入 `Include ~/.vnssh/hosts.conf`，不改动已有其他 `Host` 块。
- **可脱离 vnssh 使用**：删除 vnssh 后，只要保留 `hosts.conf` 与 `Include` 行，仍可直接 `ssh <Host名>`；密码类主机需自行处理输入方式（Keychain 集成由 vnssh 提供）。

`~/.ssh/config` 中 vnssh 未托管的条目会在 TUI 显示并标记 **ext**。

### 连接、取消与失败返回

TUI 和 `vnssh connect <Host>` 都通过 PTY 启动 OpenSSH；一次尝试无论成功、失败还是取消，都应结束这次连接，而不是停在冻结的 SSH 画面。TUI 回到列表时仍选中刚才那台主机。

- **取消**：远端 shell 尚未起来时，**Ctrl-C** 结束本地 `ssh` 并返回 TUI。登录成功后，Ctrl-C 仍发给远端（与普通 SSH 一致）。
- **二次提示**：Keychain/askpass 的第二次提示（OTP、重试等）下，**Ctrl-C** 或 **Esc** 视为取消，而不会把控制字符吃进密码行。
- **硬失败**：连接超时、Connection refused、no route to host、网络不可达、Permission denied、Authentication failed，以及常见中文「密码错误」「认证失败」等，会结束本次尝试并在状态栏显示原因。
- **看门狗**：若既无输出进展、也不是在等你输入（密码、OTP、主机密钥 yes/no），预登录阶段约 **20 秒** 后停止。TCP 握手仍使用 OpenSSH `ConnectTimeout` **5 秒**。正在等你打字时不计入这 20 秒。

每次尝试开始时会打印 `Connecting... (Ctrl-C to cancel)`。

### 旧协议自动兼容

部分旧交换机、网络设备仅支持较弱算法（如 `ssh-rsa`、`diffie-hellman-group1-sha1`、`3des-cbc`）。新版 OpenSSH 默认算法集协商失败时，stderr 常见：

- `no matching key exchange method found`
- `no matching cipher found`
- `no matching mac found`
- `no matching host key type found`

未标记的主机先用 OpenSSH 默认算法连接；只有协商失败才会改用旧算法重试。

vnssh 提供两层处理：

1. **自动学习**：默认算法失败且错误符合上述特征时，当场用兼容的 `KexAlgorithms`、`HostKeyAlgorithms`、`Ciphers`、`MACs` 等重试，成功后在 `Host` 块上方写入 `#v-legacy`，下次直接走旧算法。
2. **手工标记**：向导里把 **Legacy SSH algorithms** 设为 `y`，或在 `Host` 块上方手写 `#v-legacy`，跳过默认算法那一次。

对 `#v-legacy` 且 `HostName` 为纯 IP 的主机，还会在 `hosts.conf` 生成以该 IP 为 `Host` 的别名块，使 `ssh user@<IP>` 与 `ssh <Host别名>` 使用相同旧协议选项。

### 会话日志

每次 SSH 连接在**登录完成之后**自动将远端终端输出写入 `~/.vnssh/sessions/`：

- **按连接分文件**：每个会话独立 `.session` 文件，文件名含主机标识、端点与时间戳。
- **认证阶段不记录**：密码提示、OTP 等不写入日志。
- **实时落盘**：登录后输出经缓冲刷新至磁盘，异常退出仍可保留绝大部分内容。
- **自动归档**：退出 TUI 时，将早于本周（自然周，周一至周日）的 session 按周打包为 `YYYY-MM-DD_YYYY-MM-DD.tar.gz`，成功后删除源 `.session`；已归档周次记入 `.archive-state.json`，无需手工干预。

环境变量开关（读取逻辑见 `vnssh.py` 中 `session_logging_enabled()` / `session_archive_enabled()`）：

| 变量 | 默认值 | 作用 |
|------|--------|------|
| `VNSSH_SESSION_LOG` | 开启 | 设为 `0`、`false`、`no`、`off` 之一时关闭会话记录 |
| `VNSSH_SESSION_ARCHIVE` | 开启 | 设为 `0`、`false`、`no`、`off` 之一时关闭退出时的自动打包 |

示例：`VNSSH_SESSION_LOG=0 vnssh` 或 `VNSSH_SESSION_ARCHIVE=0 vnssh`。

### CSV 导入与导出

适合批量录入、备份或迁移主机清单：

```bash
vnssh init                              # 生成 vnssh-hosts-template.csv（幂等）
vnssh import hosts.csv                  # 导入
vnssh import --dry-run hosts.csv        # 预览，不写配置
vnssh import --force hosts.csv          # 覆盖 hosts.conf 中已有同名 Host
vnssh export                            # 写出 vnssh-hosts.csv（不含密码）
vnssh export backup.csv                 # 指定路径
```

`vnssh init` 在 `hosts.conf` 与 `Include` 已就绪时跳过初始化；当前目录已有模板时不覆盖。

| 列名 | 说明 |
|------|------|
| `category` | 写入 `#v-f:` 注释，对应 TUI Category |
| `host` | `Host` 别名（必填） |
| `hostname` | 地址（必填） |
| `user` | 用户名（必填） |
| `port` | 端口，默认 `22` |
| `password` | 非空时写入 Keychain，不进入配置文件 |
| `identity_file` | 私钥路径 |
| `auth` | `password` / `key` / `both`（或 `1` / `2` / `3`） |
| `twofa` | `y` / `n`（可选，写入 `#v-2fa`） |
| `legacy` | `y` / `n`（可选，写入 `#v-legacy`） |

导入规则：

| 目标状态 | 行为 |
|----------|------|
| 新 Host | 写入 `hosts.conf`；密码列有值才写入 Keychain |
| 已存在于 `hosts.conf` | 默认跳过；`--force` 时只改这一段 Host。没有密码列则不动 Keychain |
| 已存在于 `~/.ssh/config`（ext） | 不写入 `hosts.conf`；密码列有值才改 Keychain，空或 `-` 删除 |

表头支持常见别名（如 `folder` → `category`）。建议先 `--dry-run` 核对统计。

`vnssh export` 写出上述列，**不含 `password`**。用导出文件再 import（含 `--force`）可恢复主机配置和 `#v-2fa` / `#v-legacy`，不会因为没有密码列而删除 Keychain。空密码或 `-` 才会删除。

## 配置文件

vnssh 涉及的文件路径：

| 路径 | 内容 |
|------|------|
| `~/.vnssh/hosts.conf` | vnssh 托管的 `Host` 定义（OpenSSH 格式） |
| `~/.ssh/config` | 用户原有配置；vnssh 仅追加 `Include ~/.vnssh/hosts.conf` |
| `~/Library/Keychains/` | Keychain 中的 `vnssh` 服务密码条目 |
| `~/.vnssh/sessions/` | 会话日志（`.session`）与归档包（`.tar.gz`） |
| `~/.vnssh/history.json` | 连接使用频率（用于排序） |
| `~/.vnssh/.keychain-accounts.json` | Keychain **账户名**缓存（不含密码），避免每次启动都 dump 整个钥匙串 |

`Host` 块**上方**可选注释（均为可选，按需添加）：

| 注释 | 不写时的行为 | 写上时 |
|------|----------------|--------|
| `#v-f:分类名` | TUI Category 显示 **Uncategorized** | 显示指定分类，并参与搜索 |
| `#v-2fa` | 有 Keychain 密码时走 `SSH_ASKPASS` 常规注入；无密码则依赖手工输入 | 交互连接时通过 PTY 检测提示并注入密码，OTP/验证码在终端手工输入。向导里 **2FA / bastion** 填 `y` 即写入 |
| `#v-legacy` | 使用 OpenSSH 默认算法；若协商失败则自动学习并写入此标记 | 立即启用旧协议算法集，跳过首次失败。向导里 **Legacy SSH algorithms** 填 `y` 即写入 |

示例（三条注释可按需省略）：

```sshconfig
#v-f:生产环境
#v-2fa
Host bastion-example
    HostName 203.0.113.10
    User alice
    Port 8321
```

Category 注释可使用中文，例如 `#v-f:生产环境`。

## TUI 快捷键

| 按键 | 功能 |
|------|------|
| Enter | 连接 |
| Ctrl-N | 新建 |
| e | 编辑 |
| d | 删除 |
| ↑ / ↓ | 移动选择 |
| PgUp / PgDn | 翻页 |
| Ctrl-B / Ctrl-F | 翻页（与 PgUp / PgDn 相同） |
| Esc | 清空搜索；搜索框为空时退出 |
| Ctrl-C | 连接中（远端 shell 起来之前）：取消并回到列表 |

列表标志：**p** = Keychain 有密码，**k** = 已配置密钥，**ext** = 外部 SSH 配置，**2** = 2FA/堡垒机（`#v-2fa`），**L** = 旧算法（`#v-legacy`）。

## 命令行

```bash
vnssh                         # 打开 TUI
vnssh list
vnssh connect <Host名>
vnssh import hosts.csv
vnssh import --dry-run file.csv
vnssh export
vnssh export backup.csv
vnssh init
vnssh version                 # 打印版本
vnssh --version               # 同上
vnssh -V                      # 同上
```

| 命令 | 说明 |
|------|------|
| *(无参数)* | 启动全屏 TUI |
| `list` | 非交互列出主机 |
| `connect <Host>` | 连接指定主机（与 TUI 同一套 PTY 中继：Ctrl-C、硬失败、20 秒看门狗） |
| `import [选项] <file.csv>` | 批量导入；支持 `--dry-run`、`--force` |
| `export [file.csv]` | 导出主机 CSV，无密码列（默认 `vnssh-hosts.csv`） |
| `init` | 初始化环境并写出 CSV 模板 |
| `version` / `--version` / `-V` | 打印 `vnssh <版本号>` 后退出 |

日常浏览、搜索与连接建议直接使用 TUI；命令行适合脚本调用、批量导入/导出、查看版本，或快速连接单个 Host。

## 安全说明

**Keychain 存储**

- 密码以 Generic Password 形式存入登录钥匙串，`svce=vnssh`、`acct=<Host别名>`。
- vnssh 通过 `/usr/bin/security` 读写，脚本本身与 `hosts.conf` 中均无明文密码字段。编辑向导不会预填已存密码；留空表示保留，输入 `-` 删除。
- `~/.vnssh/.keychain-accounts.json` 只缓存账户**名**（不含密码），避免每次启动 dump 整个钥匙串。
- 其他用户或进程读取需通过 macOS 安全机制；首次访问时系统可能弹出授权对话框。
- 删除某 Host 的 Keychain 条目：`security delete-generic-password -s vnssh -a <Host名>`（vnssh 编辑/删除主机时也会同步清理）。

**配置文件**

- `hosts.conf` 可含内网地址、用户名、端口等元数据，但不包含密码；分发或备份时仍需按敏感资产对待。
- `Include` 行可被手工移除以停用 vnssh 托管配置，不影响原有 `~/.ssh/config` 其他内容。

**会话日志**

- 日志仅包含登录后的远端输出，但可能记录命令与业务数据；目录默认位于用户主目录下，应限制其他账户读取权限。
- 归档包为未加密 `tar.gz`；若含敏感操作记录，请妥善保管或定期清理。
- 可通过 `VNSSH_SESSION_LOG=0` 整体关闭记录。

## 常见问题

**Terminal too small**

- TUI 要求终端至少 16 行 × 40 列（见 `MIN_TERMINAL_HEIGHT`）。放大窗口后重新运行。

**连接卡住 / 无法回到 TUI**

- 出现 `Connecting...`、远端 shell 尚未起来时按 **Ctrl-C**，会结束本地 `ssh` 并重绘列表。
- 网络失败与认证错误应自动返回，原因显示在状态栏。
- 若在等 OTP 或 `yes/no`，输入应答或 Ctrl-C 取消。登录成功后 Ctrl-C 发给远端进程，不再交给 vnssh。

**认证失败 / Permission denied**

- 应回到主机列表并在状态栏看到错误（而不是停在密码提示）。
- 按 **e** 检查 `User`、`HostName`、端口与 `auth` 模式是否匹配。
- 密钥认证：确认 `IdentityFile` 路径存在。OpenSSH 要求私钥权限为 `600`；放在 Dropbox/iCloud 等同步目录时，重启后常被改回 `644` 导致 `Permission denied`。vnssh 会在连接前自动 `chmod 600`；也可手动执行 `chmod 600 <私钥路径>`，或把密钥拷到 `~/.ssh/`。
- 密码认证：在「钥匙串访问」中查看 `vnssh` 服务下对应 `Host` 账户；TUI 列表无 **p** 标记表示 Keychain 无条目。编辑时密码留空保留原值，输入 `-` 删除。
- 手动验证：`security find-generic-password -s vnssh -a <Host名> -w`（会回显密码，仅在安全环境使用）。

**2FA / 堡垒机异常**

- 编辑该主机，把 **2FA / bastion** 设为 `y`，或在 `Host` 块上方手写 `#v-2fa`。Keychain 须已为该 **Host 别名**（非 IP）保存密码。
- 无 `#v-2fa` 时不会启用 PTY 密码注入，复杂二次验证可能失败。
- OTP 须在 vnssh 弹出的 SSH 终端内手工输入；日志在认证完成后才开始，OTP 不会写入 session 文件。

**旧协议 / algorithm mismatch**

- 未标记主机会先用 OpenSSH 默认算法；协商失败时当场用旧算法重试，并写入 `#v-legacy`。
- 要跳过默认算法那一次，编辑主机把 **Legacy SSH algorithms** 设为 `y`，或在 `Host` 上方添加 `#v-legacy`。
- 也可直接用 `ssh -v <Host名>` 对比 vnssh 附加的算法选项是否生效（`Include` 须能被 OpenSSH 读取）。

**会话日志为空或 tail 看不到**

- 日志在登录完成后才创建；认证阶段文件可能尚未生成。
- 仅记录远端输出，本地按键不回显到日志。
- 归档仅发生在**退出 TUI** 时；`vnssh connect` 等 CLI 子命令不触发打包。

**CSV 导入被跳过**

- `hosts.conf` 已有同名 Host 时默认跳过，需 `--force` 覆盖。
- 来自 `~/.ssh/config` 的 ext 主机不会改写配置，仅在有 `password` 列时更新 Keychain。
- `vnssh export` 不含密码；再 import 只恢复配置和 `twofa` / `legacy` 标记。

## 许可

[MIT](LICENSE)
