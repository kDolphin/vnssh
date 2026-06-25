# vnssh

macOS 上的 SSH 启动器：终端 TUI 搜主机、Keychain 存密码、支持 2FA 堡垒机与会话日志。单文件 `vnssh.py`，无第三方依赖。

[English](README.md)

## 功能

- **TUI 列表**：按名称、地址、分组搜索（支持拼音首字母）
- **Keychain 密码**：密码不进配置文件，由 macOS 钥匙串管理
- **OpenSSH 集成**：自动维护 `~/.ssh/config` 的 `Include`，与现有配置共存
- **2FA / 堡垒机**：`#v-2fa` 主机自动填密码，OTP 在终端手输
- **老设备兼容**：算法不匹配时自动学习并写入 `#v-legacy`（也可手工预先配置）
- **会话日志**：登录后的终端输出写入 `~/.vnssh/sessions/`（堡垒机二次登录会单独建目标机日志）
- **CSV 批量导入**：从表格一次性导入主机

## 环境要求

- macOS
- Python 3
- OpenSSH（`ssh` 命令）
- 终端窗口建议高度 ≥ 16 行、宽度 ≥ 40 列

## 快速开始

```bash
chmod +x vnssh.py
./vnssh.py
```

**无需单独执行 `init`**。首次运行会自动：

1. 创建 `~/.vnssh/` 和 `hosts.conf`
2. 在 `~/.ssh/config` 顶部加入 `Include ~/.vnssh/hosts.conf`（若尚未存在）

### 添加第一台主机

1. 运行 `vnssh` 打开 TUI
2. 按 **Ctrl-N** 新建连接
3. 按向导填写名称、地址、用户、认证方式；密码可选，会存入 Keychain（服务名 `vnssh`）
4. 选中主机，**Enter** 连接

## TUI 快捷键

| 按键 | 功能 |
|------|------|
| Enter | 连接 |
| Ctrl-N | 新建 |
| e | 编辑 |
| d | 删除 |
| ↑/↓ | 选择 |
| PgUp / PgDn | 翻页 |
| Esc | 清空搜索 / 退出 |

列表标志：**p** = 已存密码，**k** = 已配置密钥，**ext** = 来自外部 SSH 配置。

## 命令行

```bash
vnssh list
vnssh connect <Host名>
vnssh import hosts.csv
vnssh import --dry-run file.csv
vnssh init          # 初始化 ~/.vnssh，并在当前目录生成导入模板 CSV
```

`vnssh init` 具有幂等性：若 `~/.vnssh/hosts.conf` 与 `~/.ssh/config` 中的 `Include` 行均已存在，则跳过初始化。会在**当前目录**生成 `vnssh-hosts-template.csv`（已存在则跳过）。编辑后执行 `vnssh import vnssh-hosts-template.csv` 即可导入。

## 配置文件

主机定义在 `~/.vnssh/hosts.conf`，格式与 OpenSSH 一致。可在某个 `Host` 块**上方**加注释：

| 注释 | 含义 |
|------|------|
| `#v-f:分组名` | 分组（TUI 里显示） |
| `#v-2fa` | 需二次验证（自动填密码 + 终端输入 OTP） |
| `#v-legacy` | 老设备 SSH 算法（可选；不配也会在首次失败后自动学习） |

示例：

```sshconfig
#v-f:Production
#v-2fa
Host bastion-example
    HostName 203.0.113.10
    User alice
    Port 8321
```

## 会话日志

- 默认开启，目录：`~/.vnssh/sessions/`
- 仅记录**登录成功后**的终端输出（不含 OTP 等认证阶段）
- 腾讯云堡垒机：二次登录成功后会生成独立文件，形如 `时间_目标IP_用户_via_堡垒机名.session`
- 关闭：`VNSSH_SESSION_LOG=0 vnssh`

## CSV 导入

在当前目录生成模板：

```bash
vnssh init
# 生成 vnssh-hosts-template.csv（含示例行）
vnssh import vnssh-hosts-template.csv
```

列名：`category`, `host`, `hostname`, `user`, `port`, `password`, `identity_file`, `auth`（也接受 `folder` / `group` 别名）。

`auth` 取值：`password` / `key` / `both`（或 `1` / `2` / `3`）。

## 安全说明

- 密码只存在 macOS Keychain，**不会**写入 `hosts.conf` 或脚本本身
- 会话日志可能含命令与输出，请注意 `~/.vnssh/sessions/` 权限
- 首次使用 Keychain 时系统可能要求授权

## 常见问题

**Terminal too small** — 拉大终端窗口后重试。

**认证失败** — 检查密码/密钥；按 **e** 编辑；或在钥匙串中查看服务 `vnssh`。

**2FA 主机异常** — 确认已加 `#v-2fa`，且 Keychain 里已为该 Host 名保存密码。

**老设备首次连接失败** — 再连一次通常会成功；也可预先加 `#v-legacy`。

## 许可

[MIT](LICENSE)