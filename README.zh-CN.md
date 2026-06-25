# vnssh

macOS 终端 SSH 启动器。单文件 `vnssh.py` 分发，依赖系统 Python 3 与 OpenSSH，无第三方包。

[English](README.md)

## 功能

### TUI 界面

vnssh 以全屏 TUI 展示主机列表，支持实时过滤。搜索框输入任意片段后，列表即时收窄并按相关度排序（精确匹配 Host 别名优先，其次前缀与子串匹配，再结合最近使用记录）。

可搜索字段包括：**Category**、**Host 别名**、**HostName**、**User**、**Port** 及组合标签。中文主机名与 Category 额外建立拼音索引，支持**全拼**与**首字母**匹配（例如 Category「生产环境」可用 `sc`、`schj` 等片段命中）。

未输入搜索词时，列表按最近连接记录排序。

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

### 旧协议自动兼容

部分旧交换机、网络设备仅支持较弱算法（如 `ssh-rsa`、`diffie-hellman-group1-sha1`、`3des-cbc`）。新版 OpenSSH 默认算法集协商失败时，stderr 常见：

- `no matching key exchange method found`
- `no matching cipher found`
- `no matching mac found`
- `no matching host key type found`

vnssh 提供两层处理：

1. **自动学习**：首次连接失败且错误符合上述特征时，在对应 `Host` 块上方写入 `#v-legacy`，下次自动附加 `KexAlgorithms`、`HostKeyAlgorithms`、`Ciphers`、`MACs` 等兼容选项并写回 `hosts.conf`。
2. **手工标记**：可预先添加 `#v-legacy`，跳过首次失败。

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

### CSV 导入

适合批量录入或迁移主机清单：

```bash
vnssh init                              # 生成 vnssh-hosts-template.csv（幂等）
vnssh import hosts.csv                  # 导入
vnssh import --dry-run hosts.csv        # 预览，不写配置
vnssh import --force hosts.csv          # 覆盖 hosts.conf 中已有同名 Host
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

导入规则：

| 目标状态 | 行为 |
|----------|------|
| 新 Host | 写入 `hosts.conf`；若提供密码则写入 Keychain |
| 已存在于 `hosts.conf` | 默认跳过；`--force` 时更新配置与 Keychain |
| 已存在于 `~/.ssh/config`（ext） | 不修改其配置；CSV 含密码列时仅导入 Keychain |

表头支持常见别名（如 `folder` → `category`）。建议先 `--dry-run` 核对统计。

## 环境要求

- macOS
- Python 3
- OpenSSH（`ssh`）
- 终端窗口建议 ≥ 16 行 × 40 列

## 快速开始

```bash
chmod +x vnssh.py
cp vnssh.py ~/.local/bin/vnssh    # 可选：加入 PATH，命令名 vnssh
./vnssh.py                         # 或直接：vnssh
```

确保 `~/.local/bin` 在 `PATH` 中（zsh 可在 `~/.zshrc` 添加 `export PATH="$HOME/.local/bin:$PATH"`）。

首次运行自动创建 `~/.vnssh/`、`hosts.conf`，并在 `~/.ssh/config` 加入 `Include`（已存在则跳过）。**无需单独执行 `init`**。

### 添加主机

1. 运行 `vnssh`
2. **Ctrl-N** 新建
3. 填写 category、名称、地址、用户、认证；密码可选，存入 Keychain
4. 选中主机，**Enter** 连接

## 配置文件

vnssh 涉及的文件路径：

| 路径 | 内容 |
|------|------|
| `~/.vnssh/hosts.conf` | vnssh 托管的 `Host` 定义（OpenSSH 格式） |
| `~/.ssh/config` | 用户原有配置；vnssh 仅追加 `Include ~/.vnssh/hosts.conf` |
| `~/Library/Keychains/` | Keychain 中的 `vnssh` 服务密码条目 |
| `~/.vnssh/sessions/` | 会话日志（`.session`）与归档包（`.tar.gz`） |
| `~/.vnssh/history.json` | 连接使用频率（用于排序） |

`Host` 块**上方**可选注释（均为可选，按需添加）：

| 注释 | 不写时的行为 | 写上时 |
|------|----------------|--------|
| `#v-f:分类名` | TUI Category 显示 **Uncategorized** | 显示指定分类，并参与搜索 |
| `#v-2fa` | 有 Keychain 密码时走 `SSH_ASKPASS` 常规注入；无密码则依赖手工输入 | 交互连接时通过 PTY 检测提示并注入密码，OTP/验证码在终端手工输入 |
| `#v-legacy` | 使用 OpenSSH 默认算法；若协商失败则自动学习并写入此标记 | 立即启用旧协议算法集，跳过首次失败 |

示例（三条注释可按需省略）：

```sshconfig
#v-f:Production
#v-2fa
Host bastion-example
    HostName 203.0.113.10
    User alice
    Port 8321
```

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

列表标志：**p** = Keychain 有密码，**k** = 已配置密钥，**ext** = 外部 SSH 配置。

## 命令行

```bash
vnssh list
vnssh connect <Host名>
vnssh import hosts.csv
vnssh import --dry-run file.csv
vnssh init
```

日常浏览、搜索与连接建议直接使用 TUI；命令行适合脚本调用、批量导入或在无交互环境下快速连接单个 Host。

## 安全说明

**Keychain 存储**

- 密码以 Generic Password 形式存入登录钥匙串，`svce=vnssh`、`acct=<Host别名>`。
- vnssh 通过 `/usr/bin/security` 读写，脚本本身与 `hosts.conf` 中均无明文密码字段。
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

**认证失败 / Permission denied**

- 按 **e** 检查 `User`、`HostName`、端口与 `auth` 模式是否匹配。
- 密钥认证：确认 `IdentityFile` 路径存在且权限为 `600` 左右。
- 密码认证：在「钥匙串访问」中查看 `vnssh` 服务下对应 `Host` 账户；TUI 列表无 **p** 标记表示 Keychain 无条目。
- 手动验证：`security find-generic-password -s vnssh -a <Host名> -w`（会回显密码，仅在安全环境使用）。

**2FA / 堡垒机异常**

- 确认 `Host` 块上方有 `#v-2fa`，且 Keychain 中已为该 **Host 别名**（非 IP）保存密码。
- 无 `#v-2fa` 时不会启用 PTY 密码注入，复杂二次验证可能失败。
- OTP 须在 vnssh 弹出的 SSH 终端内手工输入；日志在认证完成后才开始，OTP 不会写入 session 文件。

**旧协议 / algorithm mismatch**

- 首次报错 `no matching cipher` 等时，直接再连一次；vnssh 应自动写入 `#v-legacy`。
- 若仍未成功，手工在 `Host` 上方添加 `#v-2fa` 同级的 `#v-legacy` 行后重试。
- 也可直接用 `ssh -v <Host名>` 对比 vnssh 附加的算法选项是否生效（`Include` 须能被 OpenSSH 读取）。

**会话日志为空或 tail 看不到**

- 日志在登录完成后才创建；认证阶段文件可能尚未生成。
- 仅记录远端输出，本地按键不回显到日志。
- 归档仅发生在**退出 TUI** 时；`vnssh connect` 等 CLI 子命令不触发打包。

**CSV 导入被跳过**

- `hosts.conf` 已有同名 Host 时默认跳过，需 `--force` 覆盖。
- 来自 `~/.ssh/config` 的 ext 主机不会改写配置，仅在有 `password` 列时更新 Keychain。

## 许可

[MIT](LICENSE)