# pi-bitwarden

[English version](README.md)

给 [pi coding agent](https://github.com/earendil-works/pi-coding-agent) 的 Bitwarden 扩展：**把保险库密码安全地交给进程，而不是交给大模型**。

模型需要跑一条需要凭据的命令（API token、`docker login`、`git push`……）时，密码从 Bitwarden 直接注入到 bash 子进程的环境变量里——**密码全文永远不出现在对话里**，不发给 LLM 供应商，不写进会话文件。

## 特性

| 工具 | 作用 | 模型能看到密码？ |
|---|---|---|
| `bw_list` | 列出条目（名称/用户名/URI/id），不含密码 | ❌ |
| `bw_inject` | 取出密码注入为 bash 环境变量（逐次确认） | ❌ 只拿到"已注入 $XXX" |
| `bw_clipboard` | 复制到系统剪贴板，30 秒自动清除 | ❌ |
| `bw_reveal` | 明文返回（逐次确认 + 强警告，可配置关闭） | ✅ 用户逐次授权 |
| `/bw status\|unlock\|lock\|clear` | 管理解锁状态 | — |

## 安全模型

- **主密码**：Zenity 桌面弹窗（无桌面时 TUI 输入兜底），只通过环境变量传给 `bw unlock`，不进 argv / 日志 / 会话
- **BW_SESSION 只存在 pi 进程内存**：不落盘、不进 bash 环境（模型无法借 `bw list` 直接翻保险库）
- **输出擦除兜底**：`tool_result` 钩子把所有工具结果里的活动密码（含 base64 变体）替换为 `[BW_SCRUBBED:$VAR]`——`printenv`、`echo $VAR` 等都会被拦截
- **失败即关**（fail-closed）：无 UI 且无桌面时，确认一律拒绝
- **自动锁定**：闲置 N 分钟（默认 0=整个会话一次解锁）、`/bw lock`、`/new` `/fork` 切会话、pi 退出——锁定即清空 session key 和全部注入变量
- **审计日志**：`~/.bw/pi-extension/audit.log`（时间戳、条目名、变量名、允许/拒绝，永不记录密码）
- **env 名黑名单**：拒绝 `PATH`、`LD_*`、`NODE_OPTIONS`、`BW_*`、`PI_*` 等注入向量

### 浏览器填密码

配合 agent-browser（模型全程看不到密码）：

```bash
bw_inject item GitHub env GH_PASS          # ① 注入
agent-browser fill @e4 "$GH_PASS"          # ② 填表单
```

重复登录同一个站可以一次性导入 agent-browser 自己的凭据库，之后不再需要密码：

```bash
printenv $GH_PASS | agent-browser auth save my-app --username me@example.com --password-stdin
agent-browser auth login my-app
```

### 已知残余风险（诚实声明）

- 注入后，模型理论上可以通过网络命令外传密码（`curl` 等；输出擦除防不住），这是"密码进 bash 环境"的固有代价，靠每次注入的人工确认把关
- 单向哈希（md5/sha256）不会被擦除
- `bw_reveal` 的明文必然进入 LLM 供应商和会话文件——所以才需要逐次确认

## 安装

需要：`bw` CLI 已 `bw login`；桌面环境有 `zenity`（无桌面也可用，走 TUI）。

```bash
# 方式一：作为 pi package
pi install git:github.com/hljhljhlj/pi-bitwarden

# 方式二：开发安装（仓库内改动 + /reload 即生效）
git clone https://github.com/hljhljhlj/pi-bitwarden ~/Project/pi-bitwarden
~/Project/pi-bitwarden/install.sh   # symlink 到 ~/.pi/agent/extensions/
```

## 配置 `~/.bw/pi-extension/config.json`

```jsonc
{
  "autoLockMinutes": 0,     // 闲置自动锁。0 = 整个会话只输一次主密码
  "keepOnResume": true,     // /resume 切会话保留解锁状态（/new、/fork 始终锁定）
  "clipboardClearSeconds": 30,
  "allowReveal": true,      // false = 彻底关闭明文通道
  "maxInjectedEnv": 12
}
```

## 开发与测试

```bash
npm test    # = bash test/run.sh
```

端到端测试完全无头：mock 的 `bw` / `zenity` / `wl-copy`（`test/mocks/`）+ 每个场景一次真实的 `pi --no-session --mode json` 会话。**断言全部落在工具结果事件上**，不依赖模型复述（模型总结会复述/幻觉，工具事件是权威的）。

覆盖：加载与 bash 覆盖、未登录提示（不弹窗）、列表无泄漏、注入→环境变量→输出擦除、base64 变体擦除、剪贴板、拒绝路径 fail-closed、reveal 允许路径、**每会话只解锁一次**。

> 调试教训：mock 脚本里 `echo "$(( $(cat 多行文件) + 1 ))"` 的算术展开错误会让 bash 以退出码 0 中止脚本——确认弹窗被静默"允许"。计数器必须单数字截断写。

## 历史

本扩展替代了此前的 `bw-mcp`（盲代理 MCP，负责保险库整理/重命名/移动，密码强制打码）。pi-bitwarden 反过来解决"密码要送到进程里"的问题：env 注入 / 剪贴板 / 受控明文，三者都带人工确认。

## 许可证

MIT
