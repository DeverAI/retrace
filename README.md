# ReTrace — 软件漏洞查找分析反向工具

ReTrace 是一个以 Windows 为目标的软件漏洞查找分析反向工具，综合**网络抓包、注册表扫描、
反编译、浏览器控制、大模型深度集成**等手段，对**指定软件（选定 APP）** 进行集中观察与漏洞
排查，并将每次观察标记入库，沉淀为可检索、可进化的经验库，辅助（乃至半自动）完成漏洞发现
与分析报告。

---

## 1. 功能特性（11 大模块）

| 编号 | 模块 | 能力 |
|------|------|------|
| M1 | pcap | 基于本机 Wireshark（tshark/dumpcap）抓包与离线解析 |
| M2 | regscan | 注册表搜索 + 自启动/COM/服务等漏洞常驻点位专项检查 |
| M3 | embedding | 轻量词频-哈希向量 + 余弦相似度经验库检索（可选 AI embedding） |
| M4 | browser | Chrome/Edge Manifest V3 扩展 + WebSocket 中枢（DOM 观察/Canvas 缓解） |
| M5 | evolve | 从观察库/经验库挖掘规则、调整观察权重、输出进化报告 |
| M6 | decompile | Python / PE / Java .class 三类反编译 + 危险 API 预筛 + LLM 语义审计 |
| M7 | watcher | 选定 APP 集中观察（进程树/网络/DNS/文件/注册表时间线） |
| M8 | ai | OpenAI 兼容 API 客户端（只读顾问，不越界） |
| M9 | hunt | 观察-标记-沉淀闭环 + 数据库经验库 |
| M10 | agent | 任务式 LLM Agent（规划-审核-执行，独立审核模型） |
| M11 | screener | 筛查工作台（主入口：可筛查/可追踪/可标记，人机协作） |

另有：**任务式内容追踪（tracking）** 与 **隐私保护与系统操作门禁（privacy_guard）**。

---

## 2. 运行环境

- 操作系统：Windows（本机 win32）
- Python：3.13.x（本机实测 3.13.13）
- Wireshark：已安装（M1 抓包依赖 `tshark.exe` / `dumpcap.exe`）
- 数据库：SQLite（标准库 `sqlite3`，单文件 `retrace.db`）
- 桌面 GUI：PyQt6（唯一第三方大依赖，满足托盘/开机自启/打包）

---

## 3. 安装与依赖

```powershell
# 进入项目根目录
cd "C:\Users\Amily\Desktop\最近科创\监控"

# 安装唯一第三方依赖
pip install PyQt6
```

其余依赖全部为 Python 标准库，无需安装（遵循轻量化原则，不引入 scapy/pyshark/requests/psutil）。

> Wireshark 需自行安装，默认路径 `C:\Program Files\Wireshark\`。

---

## 4. 配置说明

配置文件为根目录 `config.json`，启动时自动加载（缺失时使用默认值）。

- **模块开关 `switches`**：`pcap / regscan / embedding / browser / evolve / decompile /
  watcher / ai / hunt / agent / screener / tracking / privacy_guard / ui`，取值 `true/false`；
  关闭某模块后，GUI/Web 均隐藏其入口，接口调用亦被门禁拦截。
- **AI 配置 `ai`**：`base_url`（OpenAI 兼容接口地址）、`api_key`、`model`、`timeout`；
  未配置 `api_key` 时 AI 相关功能返回「AI 未配置」提示，不影响其他模块。
- **Agent 审核模型 `agent.reviewer_model`**：为空则复用主模型；另含 `max_steps`、`cmd_timeout` 等。

---

## 5. 启动方式

```powershell
python main.py                 # 启动 PyQt6 桌面 + Web 控制台（默认）
python main.py --minimized     # 启动后最小化到托盘（开机自启使用）
python main.py --no-web        # 仅桌面 GUI
python main.py --no-gui        # 仅 Web 控制台
python main.py --port 9000     # 指定 Web 端口（默认 8080）
python main.py --selfcheck     # 环境自检（列出模块开关/tshark/Python 版本后退出）
python main.py --daemon        # 仅运行持久任务后台守护（无 Web/GUI）
python main.py --agent "任务"  # 命令行运行 LLM Agent（留空进入交互式）
python -m unittest discover -s tests -v   # 运行回归测试套件（35 例）
```

- **桌面 GUI**：PyQt6 主界面，含托盘图标（关闭/最小化进托盘）、开机自启开关。
- **Web 控制台**：启动后访问 `http://127.0.0.1:8080/`（仅绑定 127.0.0.1）。
- **浏览器扩展**：`extension/` 目录，Chrome/Edge 加载已解压扩展后，在中枢握手 token 下连接本机。
  扩展面板需填写中枢端口（与 `config.json → browser.ws_port` 一致，默认 8765）与 token
  （`config.json → browser.token`，后端始终校验，留空会被拒）；带参数命令（激活标签/
  DOM 观察）使用 GUI/Web 的专用按钮。

---

## 6. 使用说明

1. **筛查工作台（M11，主入口）**：扫描可疑 APP / 卸载残留 / 指纹 / 追踪痕迹，结果可筛选、
   可标记入库（写 observations）、可追踪（复用 watcher），AI 提供只读分级建议。
   - **机器指纹文件扫描**：已知模式库（Qoder/Cursor/Windsurf/Chrome/Edge/VSCode 等的 machineid、
     DIPS、Client ID、auth token）+ 未知指纹内容检测（文件名关键词 + UUID/长十六进制内容判定）。
   - **深潜扫描**（软件卸载后仍残留的隐藏痕迹）：Prefetch 执行痕迹（.pf 文件）、注册表使用历史
     （MuiCache / UserAssist ROT13 / AppCompat / BAM 系统级执行时间戳）、WER 崩溃报告残留。
   - **指纹编码逆向**：`analyze_fingerprint_format` 逆向 SQLite/JSON/DPAPI/UUID/hex 等常见编码，
     输出创建规则与改写指导；`generate_trusted_fingerprint` 生成符合规则的替换值预览（只读），
     避免改写后因格式不合被软件判不信任而重新制造指纹。
   - **AI 指纹修改指导**：`fingerprint_guidance` 带三层安全防线（前置检查 + LLM 强制【已检查】
     自检 + 后检查），基于格式逆向上下文生成修改指导，绝不自动执行，仅阻断绕过付费墙请求。
2. **抓包（M1）**：选择网卡 → 开始抓包，实时显示数据包；支持 BPF 过滤只看目标 APP 流量；
   另有离线解析（pcap/pcapng）、抓包状态、流量统计、清理已停抓包与停止全部。
3. **注册表（M2）**：关键词/路径/值/数据四类搜索（另含"路径"模式：仅按键路径匹配）+
   自启动/COM/服务等常驻点位专项检查；支持观察键管理
   （添加/移除/查看/快照/两次快照对比）与精确值读取；GUI 与 Web 均有"扫描常驻点位"入口。
4. **反编译（M6）**：选择 `.py` / `.exe` / `.dll` / `.class` 文件 → 生成符号/字符串/可疑调用报告；
   可选「AI 审计」对危险 API 做语义分级。
5. **任务追踪**：创建任务（绑定软件名称/exe/PID/观察目录）→ 启动/暂停 → 查看实时状态与事件 →
   请求 AI 摘要 → 查看审计；任务支持 REST 接口（`PUT/DELETE /api/v1/tasks/{id}` 更新/删除，
   需 `X-ReTrace` 头）。
6. **观察/经验库（M9）**：开始观察 → 收集证据 → AI 分析 → 标记完成（写 observations 并回流
   knowledge/embedding）→ 语义检索；经验索引可手工编码单条文本与保存到磁盘。
7. **AI 助手（M8）**：配置 key 后问答/报告草稿/风险分级（未配置时界面明确提示）；Web 控制台
   设置页可直接配置 base_url/api_key/model。
8. **隐私保护（privacy_guard）**：查看 APP 对敏感标识/注册表项的访问报告，系统操作需人工逐项
   审批（GUI 对话框或 Web 控制台的 confirm() 确认 + 明确原因 + 一次性批准能力），注册表修改前
   强制创建系统还原点与精确备份。

---

## 7. 目录结构

```
监控/
├── main.py               # 程序入口
├── config.json           # 配置（模块开关 / AI 设置，含密钥不入 git）
├── retrace.db            # SQLite 数据库（观察库 / 经验库 / 审计）
├── core/                 # 核心层
│   ├── coerce.py         #   全库统一布尔解析（parse_bool/as_bool/strict_bool）
│   ├── config.py         #   配置与模块开关（update_section 统一写入口）
│   ├── events.py         #   事件总线
│   ├── logger.py         #   日志 + Err.log 机制
│   ├── audit.py          #   哈希链安全审计
│   └── db/               #   SQLite 数据层包
│       ├── connection.py #     连接/事务上下文/通用执行原语
│       ├── schema.py     #     表结构 DDL
│       ├── hunt_store.py #     agents/observations/knowledge/evolve
│       └── tracking_store.py # 任务/事件/runs/守护租约/批量提交协议
├── modules/              # 能力层：13 模块（单文件或包）
│   ├── screener/         #   M11 筛查工作台包（apps/traces/cleanup/machine_fp/
│   │                     #   deep_scan/fmt_reverse/guidance/common）
│   ├── decompile/        #   M6 反编译包（py/pe/java 解析器 + AI 审计 + 特征库）
│   └── agent/            #   M10 LLM Agent（agent/executor/reviewer/tools/cli）
├── ui/                   # UI 层
│   ├── gui.py            #   MainWindow + launch_gui（页面装配）
│   ├── gui_common.py     #   QSS 主题/QThread 异步设施/控件工厂/共享助手
│   ├── pages/            #   每页一文件（overview/screener/tracking/... 共 14 页）
│   ├── web_main.py       #   Web 服务（stdlib http.server + JSON API）
│   ├── autostart.py      #   开机自启
│   ├── tray.py           #   托盘图标
│   └── static/           #   Web 静态资源（core/nav/views_*/boot.js + index/style）
├── extension/            # Chrome/Edge MV3 浏览器扩展
├── tests/                # 回归测试套件（python -m unittest discover -s tests）
├── README.md             # 本文档（用户指引）
├── Design.md             # 设计文档（当前最新状态）
├── Techniques.md         # 技术方案文档
├── Fact.md               # 用户偏好约束与事实记录
├── Future.md             # 未来需求记录
├── FreqErr.md            # 常见错误类型记录
├── Err.log               # 运行时错误日志
└── backups/              # 全量快照 zip / git bundle（不入库）
```

---

## 8. 常见问题

- **AI 功能提示「AI 未配置」**：在 `config.json` 的 `ai` 段填入 `base_url` 与 `api_key`（支持
  DeepSeek 等 OpenAI 兼容接口），或在 GUI/Web 设置页配置。
- **抓包无数据**：确认 Wireshark 已安装且 `tshark.exe` 在 PATH 或默认安装目录；部分网卡抓包
  需管理员权限。
- **注册表/文件精确归因显示为「关联推断」**：本机未启用 Sysmon 或未授权 Security 4663 对象访问
  审计时，系统只能提供关联推断（标 `confidence=correlated`），无法精确归因；需管理员启用相应审计。
- **反编译 .pyc 在打包版失败**：打包（PyInstaller）后 `.pyc` 反编译依赖系统 Python 解释器
  （`python`/`python3`），若系统未安装将降级跳过并提示。
- **浏览器扩展连接不上（403/无限重连）**：检查扩展面板的端口与 token 是否与 `config.json` 的
  `browser.ws_port` / `browser.token` 一致（首次启动会自动生成 token 并写回 config.json）；
  扩展空闲约 30 秒会休眠，由 alarms 定时唤醒重连，命令投递最多有分钟级延迟属正常。
- **运行时错误**：所有未捕获异常自动写入根目录 `Err.log`，请先阅读该文件再排查。

---

## 9. 安全与合规

- 工具仅用于**本地授权软件分析**；抓包、浏览器注入、反编译均带显式开关与审计日志。
- Web 控制台仅监听 127.0.0.1，写 API 校验自定义头 `X-ReTrace`、Host/Origin、参数白名单与请求体上限。
- LLM Agent 工具权限分级：只读工具（扫描/分析/逆向）Agent 自主调用，无需请示；
  读写工具（命令执行/文件删除/指纹修改/联网）一律须用户确认后执行，无人工通道则自动拒绝。
  所有读写操作含备份→修改→验证→回滚四步，绝不自动执行。
  仅阻断绕过付费/授权许可的请求。
- 隐私保护不篡改硬件身份、不注入第三方进程；系统变更批准权不授予 Agent。
