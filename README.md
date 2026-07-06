# codex-auth-guard

一个 CPA（CLIProxyAPI）插件：**合并 401/402/403 凭证失效保护与 429 限额保护。**

## 它做什么

1. **401/402/403 自动禁用**：Codex 凭证请求失败且状态码为 401、402 或 403 时，插件把对应 auth JSON 标记为 `disabled: true`，并在调度时跳过它。
2. **401/402/403 可选自动删除**：打开 `auto_delete_401`、`auto_delete_402` 或 `auto_delete_403` 后，对应状态码会直接删除 auth JSON，而不是只禁用。
3. **429 自动封禁**：Codex 凭证收到 429 后，插件读取 `x-codex-*` 响应头，判断命中的是 5 小时窗口还是周限额，并记录对应 reset 时间。
4. **429 自动恢复**：调度选号时，插件会跳过尚未到 reset 时间的凭证；到期后从 ban 列表移除，并把 auth JSON 标回 `disabled: false`。
5. **429 可选自动删除**：打开 `auto_delete_429` 后，429 凭证会直接删除 auth JSON，而不是进入 ban 列表。
6. **管理面板/API**：提供状态页、禁用/封禁列表、批量恢复、批量删除和设置接口。

非 Codex provider 不会被干预。

## 429 窗口判断

OpenAI 的 ChatGPT/Codex 后端在 429 时会返回一组自定义头：

| 响应头 | 含义 |
|---|---|
| `x-codex-primary-window-minutes` | `300` = 5 小时窗口 |
| `x-codex-primary-reset-at` | 5 小时窗口刷新时间（Unix 秒） |
| `x-codex-primary-used-percent` | 5 小时窗口使用率 |
| `x-codex-secondary-window-minutes` | `10080` = 7 天（周）窗口 |
| `x-codex-secondary-reset-at` | 周窗口刷新时间（Unix 秒） |
| `x-codex-secondary-used-percent` | 周窗口使用率 |

哪个窗口的 `used-percent` 到 100，就用哪个窗口的 `reset-at`。如果两个窗口都满，按较晚的周窗口恢复；如果 429 没有这些头，插件保守地按 5 小时封禁。

## Plugin Store install

This repo ships a `registry.json`. After a GitHub release is published, it can be used as a custom CPA plugin-store source:

Latest release: https://github.com/WhatGhostCode/cpa-codex-auth-guard/releases/tag/v0.1.0

```yaml
plugins:
  enabled: true
  store-sources:
    - https://raw.githubusercontent.com/WhatGhostCode/cpa-codex-auth-guard/main/registry.json
```

If you want every CPA user to see it without adding a custom source, submit the same registry entry to the official `router-for-me/CLIProxyAPI-Plugins-Store` repository.

## 安装

### 1. 准备 C 编译器

CPA 插件是原生动态库，必须用 CGO 编译。Windows 上可以安装 MinGW-w64：

```powershell
winget install -e --id MartinStorsjo.LLVM-MinGW.UCRT
```

确认 `gcc --version` 能输出版本。

### 2. 编译

也可以直接从 Release 下载对应平台的 zip：<https://github.com/WhatGhostCode/cpa-codex-auth-guard/releases/tag/v0.1.0>

```powershell
cd codex-auth-guard
.\build.ps1            # Windows
# 或
bash build.sh          # 任意平台
```

Windows 会生成 `codex-auth-guard.dll`。Linux 生成 `.so`，macOS 生成 `.dylib`。

本插件把 CPA 的 `sdk/pluginabi`、`sdk/pluginapi` 本地化到 `cpasdk/`，Go 1.21+ 即可编译。

### 3. 放到 CPA 插件目录

CPA 在 Windows amd64 上按顺序查找：

```text
plugins/windows/amd64-<variant>/
plugins/windows/amd64/
plugins/
```

推荐放到：

```text
plugins/windows/amd64/codex-auth-guard.dll
```

插件 ID 是文件名去掉扩展名：`codex-auth-guard`。

### 4. 在 config.yaml 启用

```yaml
plugins:
  enabled: true
  configs:
    codex-auth-guard:
      enabled: true
      priority: 100
      auto_enable_429: true
      auto_delete_401: false
      auto_delete_402: false
      auto_delete_403: false
      auto_delete_429: false
```

可选配置：

| 配置 | 作用 |
|---|---|
| `auth_dir` | CPA auth JSON 文件目录 |
| `disabled_state_path` | 401/402/403 禁用状态文件 |
| `ban_state_path` | 429 ban 状态文件 |
| `auto_delete_401` | 401 时删除 auth JSON |
| `auto_delete_402` | 402 时删除 auth JSON |
| `auto_delete_403` | 403 时删除 auth JSON |
| `auto_enable_429` | 429 reset 时间到期后自动恢复 |
| `auto_delete_429` | 429 时删除 auth JSON |

## Management API

资源页：

```text
/v0/resource/plugins/codex-auth-guard/status
```

API 需要 CPA 管理密钥，支持 `Authorization: Bearer <key>` 或 `X-Management-Key`：

```bash
# 401/402/403 禁用列表
curl -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://localhost:8317/v0/management/plugins/codex-auth-guard/disabled

# 恢复单个 401/402/403 禁用凭证
curl -X POST -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"auth_id":"<AUTH_ID>"}' \
  http://localhost:8317/v0/management/plugins/codex-auth-guard/enable

# 429 ban 列表
curl -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://localhost:8317/v0/management/plugins/codex-auth-guard/bans

# 手动解除单个 429 ban
curl -X POST -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"auth_id":"<AUTH_ID>"}' \
  http://localhost:8317/v0/management/plugins/codex-auth-guard/unban
```

还支持 `enable-all`、`delete-disabled`、`delete-all-disabled`、`unban-all`、`delete-ban`、`delete-all-bans`、`settings`。

## 工作流程

```text
请求完成 -> usage.handle
  |
  +- 非 codex / 非失败 -> 跳过
  +- 401/402/403
  |    +- auto_delete_xxx=true -> 删除 auth JSON
  |    +- 否则 -> 记录 disabled，标记 auth JSON disabled=true
  +- 429
       +- auto_delete_429=true -> 删除 auth JSON
       +- 否则 -> 按 x-codex-* 记录 reset_at，标记 auth JSON disabled=true

下次调度 -> scheduler.pick
  |
  +- 跳过 disabled 列表里的 Codex 凭证
  +- 跳过未到 reset_at 的 429 ban 凭证
  +- 已到 reset_at 且 auto_enable_429=true -> 移出 ban，标记 disabled=false
```

## 文件说明

| 文件 | 作用 |
|---|---|
| `main.go` | 插件主代码 |
| `main_test.go` | 行为测试 |
| `cpasdk/pluginabi/` | CPA 插件 ABI 常量 |
| `cpasdk/pluginapi/` | CPA 插件类型定义 |
| `build.ps1` / `build.sh` | 本地编译脚本 |
| `registry.json` | CPA plugin store 注册信息 |
| `.github/workflows/release.yml` | GitHub Release 构建与发布 workflow |
