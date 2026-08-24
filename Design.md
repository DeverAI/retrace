# Design.md — 软件漏洞查找分析反向工具（核心设计文档）

> 本文件只记录架构与设计决策，不包含具体代码实现。

## 0. 项目目标

构建一个"软件漏洞查找分析反向工具"（以下简称 ReTrace），以 Windows 为目标平台，
综合网络抓包、注册表扫描、反编译、浏览器控制、大模型深度集成等手段，对**指定软件
（选定 APP）**进行集中观察与漏洞排查，并将每次观察标记入库，沉淀为可检索、可进化的
经验库，辅助（乃至半自动）完成漏洞发现与分析报告。

## 1. 用户明确的需求清单（9 大模块）

| 编号 | 需求 | 模块名 |
|------|------|--------|
| M1 | 基于互联网 Wireshark 抓取工具 | pcap |
| M2 | Regedit 注册表搜索 | regscan |
| M3 | 高效 Embedding | embedding |
| M4 | 浏览器插件完整控制权 | browser |
| M5 | 自我进化 | evolve |
| M6 | 多类别反编译 | decompile |
| M7 | 选定 APP 集中观察 | watcher |
| M8 | 深度集成大模型帮助 | ai |
| M9 | 标记观察的数据库 & 经验库 | hunt |
| M10 | LLM Agent（高级/可选：任务式规划） | agent |
| M11 | 筛查工作台（主入口：可筛查/可追踪/可标记） | screener |

## 2. 用户确认的决策（含提问环节补充）

- **全局 AI Agent**：用户允许引入，接入方式为 **OpenAI 兼容 API**（需用户在配置中提供 base_url 与 key，支持 DeepSeek 等）。
- **界面形态**：PyQt6 桌面 + Web 双形态（2026-08-12 用户确认）。桌面以 **PyQt6** 为主界面；
  Web 控制台保留为第二入口（本地 http.server + 打包静态资源，可随 exe 一起打包，并非不可打包）。
- **桌面细节**：QSystemTrayIcon 托盘（关闭/最小化进托盘）；**开机自启开关**（写 HKCU
  Run 注册表，启动参数 `--minimized` 直接进托盘）；用户已允许，自启可在 UI 内关闭，写入与
  关闭均记 audit_log 审计。
- **反编译范围（本期）**：Python 字节码、Windows PE（PE32/PE32+）、Java .class 三类，纯本地解析实现。
- **浏览器插件目标**：Chrome / Edge（Manifest V3）。
- **开发节奏**：全部模块都实现为可用版本，不赶进度、保证质量，"做完不急"。
- **轻量化（奥卡姆剃刀）**：除非必要，不引入大第三方包；首选 Python 标准库。
- **模块开关机制**：源码内设 `ENABLE_XXX = True/False`，关闭时隐藏入口与接口调用，
  便于演示与排错。

## 3. 总体架构

```
┌────────────────────────────────────────────────────┐
│  UI 层   PyQt6 桌面 (主界面: 托盘/开机自启)          │
│          Web 控制台 (stdlib http.server + 静态页)    │
│          ├ 浏览器插件中枢 (WebSocket 桥)             │
├────────────────────────────────────────────────────┤
│  编排层  hunt.py — 漏洞查找主流程/标记观察工作流      │
│          evolve.py — 自我进化调度器                  │
│          events.py — 事件总线 (模块解耦的纽带)        │
├────────────────────────────────────────────────────┤
│  能力层  M1 pcap | M2 regscan | M3 embedding |      │
│          M4 browser | M6 decompile | M7 watcher |   │
│          M8 ai                                       │
├────────────────────────────────────────────────────┤
│  数据层  config.json | SQLite(观察库/经验库)         │
│          Err.log | FreqErr.md | reports/             │
│          由 db.py + logger.py 统一管理               │
└────────────────────────────────────────────────────┘
```

设计要点：
1. **事件总线**：模块之间不直接互相 import，通过 events.py 发布/订阅事件
   （如 `packet.captured`、`registry.hit`、`decompile.done`），便于模块开关与扩展。
2. **观察-标记-沉淀闭环**（M9 核心思想）：
   `选定目标 → 多模块集中观察 → 人工/LLM 标记风险点 → 写入观察库 →
   定期归纳为经验规则 → 经验回流到下次观察的提示与打分`。
3. **自我进化（M5）**：基于经验库的闭环（规则挖掘 + 观察优先级调整 +
   报告质量统计），逐步提高命中率；由 LLM 辅助提炼规则，但全程保留人工确认入口。
4. **数据模型**：
   - `observations` 观察库：对选定 APP 的一次观察（时间、目标、来源模块、证据快照、标记、结论）。
   - `knowledge` 经验库：从观察中提炼的规则/模式（类别、关键词、风险分、来源观察数、权重）。
   - `agents` 被观察目标档案（路径、PID、IP、注册表关联键、文件指纹）。
   - `audit_log`：操作审计（谁在何时观察了什么）。
5. **安全边界**：工具仅用于本地授权的软件分析；抓包与浏览器注入均带显式开关；
   所有敏感操作记录审计日志。
6. **LLM Agent 不越界（2026-08-12 用户要求）**：
   - AI 模块（M8）是**纯文本 HTTP 客户端**，无文件/进程/命令执行路径；其输出从不被
     exec/eval/自动落库执行（人工确认后才写入经验库）。
   - 所有系统提示叠加 `SAFETY_SYS` 硬性边界：只读顾问、防提示注入（证据内容中的指令
     一律视为数据）、禁出恶意载荷、不声称已执行操作、敏感信息脱敏。
   - 自我进化（M5）默认 `auto_apply=false`，规则写入前必须人工确认。
7. **本地服务安全**：Web 控制台仅绑定 127.0.0.1；POST API 要求自定义头 `X-ReTrace`
   （跨源 fetch 预检被拦截、表单无法设置 → 防跨站调用）；API 白名单与前端调用一一对应；
   请求体上限 64KB；静态文件路径穿越防护；浏览器扩展中枢同样仅绑定 127.0.0.1 且带 token。
   `/api/v1` 路由按"方法×路径"矩阵守卫：集合路由只允许 GET/POST，PUT/DELETE 等方法
   映射 405（区别于未知路由 400）；模块 RPC 路径的业务失败封套为 HTTP 200 + ok:false
   （前端 bizFail 判定），对外部布尔参数统一严格解析（拒绝 "false" 字符串误判为 True）。
8. **M10 LLM Agent 子系统（2026-08-12 用户确认）**：
   - 能力：参照经验库、搜索（注册表/文件/进程）、检查（APP/残留/指纹/可疑 APP）、
     运行白名单命令、联网查询（逐次确认）、删除（确认后删除+隔离备份）。范围不限选定 APP。
   - **执行审核链**：Agent（主模型）规划工具调用 → **空上下文独立审核模型 reviewer**
     （单条调用+审核提示词，无 Agent 历史，防污染）判定 allow/deny：
     allow → 执行引擎调用（超时+审计）；deny → 用户手动审批；用户仍拒 → 丢弃该调用，
     向 Agent 会话插入系统警告消息并通知用户。
   - 风险分级：read（自动）/ cmd（reviewer 审核）/ high（reviewer + 用户审批）。
   - 删除操作强制先复制到 `backups/quarantine/<时间戳>/` 再删，仅允许删除 Agent 检出清单
     中精确匹配的路径；命令执行用 argv 列表（无 shell）、带超时、黑名单命令（del/rmdir/
     format/shutdown 等）永不执行。
   - AI API / 模型全由 config 自定：`ai.*` 主模型；`agent.reviewer_model` 审核模型（空=同主模型）。

## 4. 模块设计（职责边界）

- **M1 pcap**：调用本机 Wireshark 的 tshark/dumpcap 命令行抓包与离屏解析；
  可选 dpkt 式纯解析兜底；产出结构化数据包摘要事件。
- **M2 regscan**：基于标准库 winreg 递归扫描注册表，支持关键词/路径/值/数据四类模式
  搜索；对"自启动、COM 注册、AppInit、服务项"等漏洞常驻点位做专项检查。
- **M3 embedding**：轻量本地方案（词频-哈希向量 + 余弦相似度）做经验库检索；
  若用户配置了 AI key，可切换 OpenAI 兼容 embedding 接口（模块内留双实现与开关）。
- **M4 browser**：自带 WebSocket/HTTP 中枢 + Chrome/Edge Manifest V3 扩展；
  支持标签页/页面快照、DOM 观察与按站点 Canvas 缓解；通用 JS `eval` 注入已因本机 Web API
  越权风险删除，为前端隐私/敏感泄露提供只读观察通道。连接可靠性：扩展用 chrome.alarms
  定期唤醒 service worker 并重连（MV3 SW 空闲约 30s 即被终止，setInterval 不可靠），
  中枢空闲读超时 75s（明显大于 30s 心跳，避免阈值竞态断链）；带参数命令（activate
  {tabId}/observe_dom {enabled}）由 GUI/Web 专用按钮下发，扩展侧对缺参做守卫。
- **M5 evolve**：定期从观察库/经验库挖掘规则、统计各观察策略的命中率、
  调整模块观察权重；输出"进化报告"。
- **M6 decompile**：三类解析器（Python dis、PE 结构解析、Java class 常量池/方法表），
  输出符号表、字符串、可疑调用（exec/eval/反射/越界 API）清单作为漏洞预筛信号。
- **M7 watcher**：把"选定 APP"做成持续观察任务：进程树、网络连接、文件改动、
  注册表写入、DNS 解析联动，产出一张"目标行为时间线"。
- **M8 ai**：OpenAI 兼容 API 客户端（标准库 urllib 实现），提供上下文问答、
  报告草稿生成、规则提炼、风险分级打分；全局唯一切口，未授权时不启用（记 Fact）。
- **M9 hunt**：主流程编排器 + 观察标记 + 数据库写入 + 经验回流，
  提供"观察一次 → 得到分析卡片"的完整闭环（与 M11 共用 observations 观察库）。
- **M11 screener 筛查工作台（2026-08-13 用户定位：人机协作，不二选一）**：
  即点即用的确定性筛查（扫描可疑APP/残留/指纹/追踪），结果可筛选（类别/风险）、可标记入库
  （写 observations）、可追踪（复用 watcher）；AI 作只读辅助（analyze_with_ai 对结果一键
  分级建议，不执行工具）；自由 Agent（M10）保留为高级功能，不占主界面入口。
- **M10 agent**：任务式 Agent（规划-审核-执行-回填），用于一次性复杂任务；默认非主入口。

## 5. 关键技术决策

- 平台：Windows（win32），已确认 Python 3.13.13、Wireshark（tshark/dumpcap）已安装。
- 语言：Python 3.13；前端为原生 HTML/JS/CSS（无框架），全部由 Python 静态伺服。
- 数据库：SQLite（标准库 `sqlite3`），单文件 `retrace.db`。
- 配置：`config.json`（模块开关、AI 设置、路径、观察策略），启动时加载。
- 错误处理：运行时异常统一捕获写入 `Err.log`（logger 内建自动存错），
  修复后清空；不吞错。
- 演示友好：模块开关全局集中管理，关闭后 UI 与事件总线都不出现该模块入口。
- **GUI 后台任务生命周期（2026-08-13 修复）**：阻塞任务统一走 `_run_async`（QThread +
  Worker 强引用 + 跨线程信号中继）；页面数据预加载一律**惰性**（首次显示才加载），
  不在窗口构造时启动线程，保证稳定退出不崩溃。
- **命令执行安全（2026-08-13 查修强化）**：Agent `run_command` 除命令白名单/黑名单外，
  增加**子命令级防护**（ipconfig 仅查询、tshark 禁写文件、reg 禁写）；白名单命令以
  CREATE_NO_WINDOW 执行。观察数据一致性：DNS 解析按"记录名称/Record Name"行内取值。
- **浏览器中枢 Token 持久化（2026-08-13 查修）**：首次启动生成 token 后写回 config.json，
  保证扩展跨重启可连接；token 旋转记审计。

## 6. 前端视觉优化（2026-08-13，用户要求"简洁风+发挥审美"）

- **设计语言**：暗色安全控制台风格，与 Web 控制台色板统一（#0b0f17 底 + #2dd4bf 青色强调）。
- **PyQt6 GUI**：引入 QSS 全局样式表，侧栏品牌头+样式化导航+状态底栏，内容区卡片化（QGroupBox
  圆角卡片+分区标题），表格/输入/按钮统一暗色风格，按钮区分主/次层级。
- **Web 控制台**：在现有暗色主题基础上精修间距、动画、代码组织一致性。
- **重构原则**：功能逻辑不变（QThread 生命周期/Agent 安全链/Web 安全防护全部保留），仅重构视觉层。
- **简洁优先**：去除冗余装饰，留白克制，有限强调色，统一字号层级。

## 7. 文档与备份纪律（遵循 AGENT.txt）

- 项目文档仅存在于项目根目录：Design.md / Techniques.md / Fact.md / Future.md /
  FreqErr.md / Err.log / todo.md / done.md / backups/ / dev_log/ / updates/。
- 每轮完成后：todo 清空、done 归档到 updates/、写 dev_log/ 日期日志、
  阶段性备份到 backups/。

## 8. 任务式内容追踪与常驻守护架构（2026-08-13 本轮 overhaul）

- **统一任务域**：新增持久化 tracking task，任务明确绑定指定软件（名称、可执行文件、PID、
  观察目录）与追踪策略；状态、心跳、检查点、最近错误、采集事件均写入 SQLite，UI 重启不丢失。
- **后台守护**：后端启动时由单一 daemon supervisor 恢复 enabled/running 任务，定期调度采集；
  可用 `--daemon` 无界面常驻，也可随 Web/PyQt 宿主运行。停止应用时只停止工作线程，不删除任务。
- **内容追踪**：每个任务对指定软件的进程、网络连接、DNS、文件变化和注册表变化形成结构化事件；
  事件带 task_id、target、severity、source、时间与稳定指纹，重复事件聚合而非无限刷屏。
- **AI 工具深化**：AI 不直接访问系统。任务事件先经确定性聚合形成受限快照，再由 AI 生成风险摘要；
  AI 请求、策略判定、工具审核、执行结果均关联 task_id/run_id 并进入审计链。AI 失败不阻断采集。
- **安全审计**：审计记录增加 actor、action、resource、outcome、risk、request_id、结构化详情与
  hash-chain 字段；密钥、token、Authorization、cookie 等敏感值统一脱敏。提供完整性校验接口。
- **单一后端契约**：HTML 与 PyQt 不再各自维护业务逻辑，统一调用 task service；Web 使用版本化
  JSON API，PyQt 调同一 Python service facade，返回结构一致，保证全栈行为兼容。
- **交互主线**：创建任务 → 启动/暂停 → 查看实时状态与事件 → 请求 AI 摘要 → 查看审计；
  任务列表为主入口，旧的临时 watcher 能力保留为底层采集实现与兼容入口。
- **默认安全**：Web 仅监听 loopback；写 API 校验 Origin/Host、自定义请求头、JSON content-type、
  请求体大小与参数白名单；任何高风险工具仍需独立 reviewer 与人工批准。

## 9. APP 全局行为归因追踪（2026-08-14）

- 用户明确要求追踪指定 APP 的**注册表、DNS、文件行为**，不能仅依赖预先指定目录。
- 采集采用分层证据模型：优先消费 Windows Sysmon Operational 日志，对 FileCreate、Registry、
  DNS Query 事件按 Image/PID 精确归因；其次读取 Windows Security 4663 对象访问日志，按
  ProcessName 归因文件/注册表访问；系统未启用上述日志时才使用 DNS 缓存差分与目标相关注册表
  快照作为“关联推断”。
- 每条事件必须标记 `confidence=exact|correlated` 和 `provider`。关联推断不得显示为 APP 的确定行为。
- 文件路径由系统审计事件自动发现并进入时间线；手工观察目录保留为补充基线，而非必填条件。
- 系统能力探测只读进行，不自动安装 Sysmon、不自动修改 audit policy/SACL；界面明确显示当前可用
  provider、精确归因能力及缺失原因，避免静默降级。
- 检查点持久化 Windows Event RecordID，守护重启后从上次位置继续，避免重复列举历史事件。
- 注册表事件必须进一步区分读取/枚举、写值/建项、删除与权限操作；“读取/枚举”只有在 Security
  4663 同时提供目标进程、注册表对象和访问掩码时才标为精确。现有相关项快照只能证明 APP 名称/
  路径与注册表内容有关，不得反推 APP 已读取该项。
- 每个注册表证据展示 APP 映像、PID、注册表键、访问类别、原始访问掩码、provider、置信度和
  EventRecordID，使“哪个程序以何种方式碰了哪个项”可查询、可审计。

## 10. 隐私保护与系统操作门禁（2026-08-14）

- **目标**：在不修改第三方 APP 文件、不注入其进程的前提下，减少 APP 对宿主硬盘序列号、MachineGuid、
  计算机名、网卡标识和受保护注册表内容的访问，并把相关尝试关联到任务时间线。
- **真正阻止优先使用隔离**：Windows Sandbox 采用专用 staging 副本只读映射、默认禁网、禁剪贴板、
  禁 vGPU/音视频/打印和 ProtectedClient。该模式隔离宿主注册表和文件，但不承诺隐藏全部 CPU/GPU/
  计时特征；staging 要求管理员完整性级别、Administrators/SYSTEM ACL 和运行期拒写共享句柄，防普通
  同用户 APP 篡改，但不能对抗同等管理员权限宿主进程。AppContainer 作为后续兼容路径。
- **隔离与遥测分开表述**：当前为“强隔离、无 guest 内部遥测”。宿主 Sysmon/Security 看不到 guest 内
  APP 的注册表/DNS/文件访问，因此不得把宿主时间线宣传为沙箱内部访问列表。后续若加入签名 guest
  collector，其输出也必须标为 guest 自报而非不可伪造审计。
- **宿主观察不是事前阻断**：Security/Sysmon 精确注册表事件匹配敏感规则后生成 `privacy.alert`；没有
  AppContainer/签名内核驱动时，宿主日志只能证明已经发生访问，界面不得显示为“已拦截”。
- **禁止高风险伪装**：不内置硬盘序列号/BIOS/MachineGuid 篡改，不自动写网卡驱动 `NetworkAddress`，
  不承诺规避许可、封禁或风控。MAC 隐私优先打开 Windows 官方“随机硬件地址”设置。
- **Canvas 防护范围**：仅作用于用户安装的 ReTrace 浏览器扩展，默认关闭且按顶级站点显式启用；私密
  salt + 顶级站点派生稳定低位扰动，降低第三方 iframe 跨站稳定性。扰动为**确定性整图噪声**
  （每像素 RGB 按 (seed,x,y) 派生 ±2 内偏移，同站点同 seed 输出一致、跨站点不同），仅覆盖 2D
  Canvas；postMessage 事件标为页面可伪造的 correlated 提示，不覆盖 WebGL/Audio/字体等完整指纹面。
  派生 seed 是"确定性、按站点稳定"的值而非对页面不可观测的秘密（seed 注入 MAIN world 供扰动
  函数使用），注释与 UI 均如实说明。Canvas 启停（set_canvas_guard）已纳入 Web RPC 白名单，
  与扩展 popup 用户手势、PyQt 本地界面并列；三个路径同样要求明确原因（≥12 字，popup 由用户
  显式填写），按顶级站点 allowlist 注入；popup 路径的设置随隐私事件上报，中枢写 audit_log 审计。
- **系统操作双门禁（2026-08-15 用户确认 Web 同为审批面）**：Agent 只能提交 action、参数、明确原因
  和影响，不能批准或执行。HTML 与 PyQt 都作为人工审批面：HTML 在浏览器内用 confirm() 对话框 +
  明确原因（≥12 字）+ 确认短语把预案（plan）转换成 10 分钟过期、单次消费的 approval capability，
  再由中央 effect gate 执行；确认短语只是轻量一致性校验（非机密），真正的人工门槛是用户主动点击
  确认并复核原因。跨站/跨源调用仍由 X-ReTrace 头 + Host/Origin 白名单阻断。
- **注册表所有权边界**：近期访问仅是依赖证据，不代表所有权。首版默认拒绝 HKLM；HKCU 也只允许用户
  先登记并绑定 task_id + EXE SHA-256 的 `Software\\厂商\\产品` 精确子树。Classes/COM/协议/Policies/
  Run/App Paths/Windows 核心/系统身份范围确定性拒绝。
- **可恢复性**：计划固定 64 位视图及值类型/内容/键时间摘要；执行开始和备份完成后分别重验。修改前
  必须成功创建系统还原点，并把精确目标值用 Windows DPAPI 加密为 30 天恢复材料；不再导出可能包含
  账号/token 的整个父子树。写后回读验证，失败尝试值级回滚；恢复材料不称为事务保证。

## 11. 留样扫描与批量清理（2026-08-14）

- **目标**：像 Revo/Geek 那样，不依赖安装目录，用关键词从注册表全树 + 文件系统反向定位某软件的
  残留痕迹（注册表键/值、自启动项、文件、目录），列为可勾选清单，批量一键清理。
- **扫描（只读）**：复用 regscan 全树搜索 + autostart_points，再扫用户目录（APPDATA/LOCALAPPDATA/
  ProgramData + 可选 install_dir）中匹配关键词的目录；每项统一带 `type`（registry_key/registry_value/
  file/dir/startup）与 `target`（可操作路径），风险分级（系统身份/核心项标高风险）。
- **清理（受控副作用）**：**强制先创建 Windows 系统还原点**（失败则整体中止，绝不裸删），这是硬性
  门禁；随后逐项清理，删除前备份——文件/目录移动进 `backups/quarantine/`，注册表键/值导出/记录为
  可恢复材料。系统身份项（MachineGuid/BIOS/磁盘序列号/网卡等）与 `_REGISTRY_DENY` 名单**确定性拒绝**，
  即使被勾选也跳过并报告。
- **权限与审计**：批量清理需管理员（还原点所需）；全程 `audit.record` 记录 action/resource/outcome/risk。
- **前端**：GUI 筛查工作台 + Web 控制台均提供「留样扫描 → 勾选 → 一键清理」入口，业务逻辑走同一
  screener facade（单一后端契约）。
- **卸载反查（2026-08-14 强化）**：扫描 HKLM/HKCU 的 `...\CurrentVersion\Uninstall`（含 Wow6432Node），
  读取 DisplayName/InstallLocation/Publisher/UninstallString 精确定位；「卸载条目在但主 exe 缺失」判为
  残留，产出可清理的卸载条目（registry_key）+ 安装目录（dir）。文件扫描从顶层子项下钻 2-3 层，
  并对 InstallLocation 精确下钻，替代纯关键词模糊匹配。
- **可恢复闭环（2026-08-14）**：清理时写 manifest.json（target → 备份路径映射），新增
  `restore_traces` 从 quarantine 一键还原文件/目录/注册表键/值；新增 `preview_cleanup` 纯预览
  （列出将清理/将拒绝项，不执行、不建还原点），前端在清理前渲染完整清单 + 风险 + 备份位置。

## 12. 数据管理闭环补齐（2026-08-15）

- **追踪任务可删除/可编辑**：模块层新增 `tracking.delete_task` / `tracking.update_task`（复用 db 层
  delete/update，审计记录）；`_v1` 增 `DELETE/PUT /api/v1/tasks/{id}`；GUI/Web 任务页增删除与编辑。
- **watcher 目标可删除 + GUI 补停止**：Web/GUI 增 remove_target 与停止入口，与 web_main ALLOWED 同步。
- **观察/经验库可删除**：db 层增 delete_observation/delete_knowledge；Web/GUI 设置页增删除按钮；
  experience set_knowledge_enabled 停用入口一并暴露。
- **注册表授权范围可撤销**：privacy_guard 增 remove_registry_scope（走审计 + 确认短语），Web vPrivacy
  展示现有 scope 并支持撤销。
- **运行历史与审计可见**：task_runs / audit_entries 两端 UI 增加展示，不再只提供 API。

## 13. 反编译危险 API 的 LLM 语义审计（2026-08-15）

- **背景**：M6 decompile 现有静态规则字典（PY/PE/JAVA_DANGER）只能做确定性匹配，无法区分
  "危险 API 被危险使用"与"参数硬编码/常规使用"的误报。
- **能力**：新增 `decompile.ai_audit(path)`，复用全局 AI Agent（ai.chat），对静态扫描得到的
  danger ≥ 0.5 的调用做一次只读语义审计，逐条输出"真危险/疑似误报/常规使用 + 理由 + 建议验证步骤"。
- **约束**：仍遵守 AI 不越界边界（SAFETY_SYS 只读顾问、防注入、不输出恶意载荷、不声称已执行）；
  AI 未配置时降级返回静态评分 + 明确"AI 未配置"提示，不报错、不阻断；仅作增强信号，不替代静态规则。
- **建议2 暂缓（记录候选）**：证据图谱聚类自动生成可复用狩猎剧本（MiniMax-M3）因"证据图谱/聚类/
  狩猎剧本"三者数据边界未定义，本轮不实现，避免过度工程。

## 14. 通用机器指纹文件扫描

- **目标**：不仅扫描注册表和文件系统残留，还要发现软件在用户目录中留下的**机器指纹文件**（machineid、DIPS、Client ID、auth token 等），这些文件通常隐藏在 `%APPDATA%` / `%LOCALAPPDATA%` 深处，常规卸载不会清理。
- **指纹模式数据库**：`screener.FINGERPRINT_FILE_PATTERNS` 定义了已知软件（Qoder/Cursor/Windsurf/Aider/Cline/Copilot/Chrome/Edge/VSCode/Codex/Claude Code/Cody 等）的指纹文件路径模式，每条含 vendor/product/dir/file/desc/risk/category。
- **扫描函数**：`screener.scan_machine_fingerprints(keyword="")` 遍历用户目录，按模式匹配，返回命中文件的路径、大小、修改时间、风险等级和小文件预览（前 64 字节）。keyword 为空时返回全部命中，非空时按厂商/产品名/描述过滤。
- **前端**：Web 控制台筛查工作台新增「④ 机器指纹文件扫描」卡片，支持关键词过滤。
- **风险分级**：高（设备唯一标识 UUID、认证令牌）/ 中（状态文件、blob 存储）/ 低（启动参数）。
- **与留样扫描的关系**：`scan_software_traces` 走注册表全树+自启动+卸载反查+文件系统关键词下钻；`scan_machine_fingerprints` 走已知模式精确匹配。两者互补。
- **通用指纹内容检测（模式库之外）**：`scan_generic_fingerprints` 不依赖厂商清单，按两条独立证据判定——①文件名命中 machine-id/device-id/client-id 等标识类关键词；②内容 ≤256 字节且为 UUID 或 32-64 位十六进制串。深度受限（≤3 级）+ 上限 30 项，防止全盘遍历失控。实测可发现模式库外的隐藏指纹（如云平台 vminit 的 PWD_UUID）。
- **深潜扫描（卸载后仍残留的隐藏痕迹）**：
  - `scan_prefetch_traces(keyword)`：扫描 `C:\Windows\Prefetch\*.pf`，还原 .pf 内嵌的完整 exe 执行路径与最后执行时间；系统禁用 Prefetch 时如实返回空列表。
  - `scan_usage_history(keyword)`：四源并查注册表使用历史——MuiCache（Shell 应用名缓存，值名即 exe 路径）、UserAssist（值名为 ROT13 编码路径，含运行计数）、AppCompatFlags Compatibility Assistant Store、BAM（`HKLM\SYSTEM\...\bam\State\UserSettings\<SID>` 系统级最后执行 FILETIME 时间戳，需管理员可读）。任一源不可读/不存在时静默跳过并保留其余源结果。
  - `scan_wer_traces(keyword)`：扫描用户与全机 WER ReportArchive/ReportQueue 的崩溃报告残留（目录按应用名命名，卸载后仍保留）。
- **GUI/Web 双入口**：GUI 筛查工作台 ①卡增「已知指纹文件/未知指纹内容」按钮 + 新增「②½ 深潜扫描」卡；Web 同布局增「⑤ 深潜扫描」卡。所有新函数纳入 web_main ALLOWED 白名单。

## 15. 指纹编码格式逆向（可信改写支持）

- **背景**：直接修改指纹文件若不符合该格式的"创建规则"（类型/长度/编码/加密/页结构错误），软件会判定不信任并**重新生成新指纹**，导致"去除/更新"失败。因此需要先逆向指纹文件的编码格式，输出创建规则与改写指导。
- **格式解析器 `screener.analyze_fingerprint_format(path)`**（只读）：识别 6 类格式——
  - `uuid_text`：36 字符 UUID 纯文本（替换须保持 8-4-4-4-12 与版本位/变体位合法）
  - `hex_uuid`：32 字符十六进制标识（可带连字符装饰，如 Qoder `cache\id`）
  - `json`：递归遍历叶子值分类——uuid / hex32（如 `device_id_salt`）/ hex64 / hex_uuid / dpapi_blob / unix_timestamp（10 位秒级，数值与字符串两种形态）/ numeric_string / string；身份类键名（id/device/install/salt/token 等）与时间类键名单独标记
  - `dpapi_blob`：base64 DPAPI 密文（magic 8 字节 `01 00 00 00 D0 8C 9D DF` 在前 40 字节内搜索，兼容 "DPAPI\x01" ASCII 前缀变体）——机器+用户绑定，无法直接伪造
  - `sqlite`：magic `SQLite format 3`；只读列出表/列/身份类列/行数；检测 -wal/-shm 侧车文件并提示"软件须已退出才可改"
  - `binary`：未识别二进制，不建议字节级改写
- **输出三要素**：`format_rules`（软件信任判据）/ `identity_fields`（身份字段定位与预览，敏感值截断）/ `rewrite_guidance`（怎么改才被信任）+ `risk`（直接改写触发重建的概率分级）。
- **替换值生成 `screener.generate_trusted_fingerprint(path)`**（只读预览，不写盘）：UUID 类给新 `uuid4()`；hex32 给 16 字节随机 hex；hex64 给 32 字节哈希；任意 hex 按原长度生成；JSON 逐字段给同类型替换值并单列 dpapi_blob 特殊项；SQLite/DPAPI/二进制不给内容，只给操作路径指导（行级 UPDATE 或整体删除重建）。
- **实测验证**：Qoder `machineid`→uuid_text、`cache\id`→uuid_text（36 字符 UUID）、`Local State`→json（encrypted_key=dpapi_blob、installation_date2=unix_timestamp）、`Preferences`→json（device_id_salt=hex32）、`DIPS`/`SharedStorage`→sqlite（DIPS 含 meta/config/bounces/popups 4 表）。生成值自洽性断言（替换值必须再次通过格式校验）纳入 `_verify_fmt.py` 回归。

## 16. 指纹修改 AI 指导（带强制安全自检）

- **背景**：用户需要 AI 指导如何修改指纹值、生成合法替换值、安全写盘。但直接让 LLM 指导指纹修改有合规风险——可能帮助绕过付费/授权。
- **安全门槛三层防线**：
  1. **确定性前置检查**（代码层，LLM 前）：受保护路径拒绝、运行中 exe 拒绝、意图关键词黑名单拦截（付费/VIP/注册码/破解/激活码等）
  2. **LLM 系统提示强制自检**（模型层）：要求 LLM 回答前必须评估①是否绕过付费墙②是否损害系统；通过则输出【已检查】标记；绕过付费墙则拒绝
  3. **【已检查】后检查**（代码层，LLM 后）：若回答不含【已检查】标记，自动追加"安全自检缺失"警告
- **硬行为边界**：绝不自动执行任何命令/写盘；所有步骤均为"人工审查后手动执行"；涉及写盘必须包含备份→修改→验证→回滚四步。
- **上下文注入**：LLM 不凭空猜格式——`fingerprint_guidance` 先把 `analyze_fingerprint_format` 的格式逆向结果 + `generate_trusted_fingerprint` 的合法替换值作为上下文注入系统提示，让 LLM 基于确定性事实生成指导。
- **入口**：Web vScreener「⑤ AI 指纹修改指导」卡；GUI ScreenerPage ②卡「AI 指导（安全自检）」按钮。

## 17. Agent 工具权限分级（只读自由 / 读写请示）

- **背景**：M10 Agent 原有三级权限（read 自动 / cmd 审核后自动或请示 / high 请示）过于模糊——cmd 工具被 reviewer allow 后自动执行，用户无法干预。新协议简化为两级：
  - **只读（RISK_READ）**：Agent 自主调用，无需请示（reviewer deny 除外）
  - **读写（RISK_CMD / RISK_HIGH）**：一律请示用户；无人工通道（confirm_cb=None）时一律拒绝
- **新增 8 个只读工具**：`scan_fingerprints` / `scan_software_traces` / `analyze_fingerprint_format` /
  `generate_trusted_fingerprint` / `scan_prefetch_traces` / `scan_usage_history` /
  `scan_wer_traces` / `modify_fingerprint`（最后一个为高风险读写）
- **`_approve` 新逻辑**：`if risk == RISK_READ: return True`（reviewer deny → 仍需确认）；
  `else: return _confirm(cb, ..., forced=True)`（所有读写必须请示）
- **系统提示词更新**：`AGENT_SYS` 明确区分两类权限 + 新增硬边界（绝不自动执行读写、不指导绕过付费墙）
- **入口复用**：CLI（`cli.py` _confirm 弹框）、GUI（AiHelperPage _confirm QMessageBox）、Web（未来 HTTP 审批通道）


## 18. 全量架构检修（2026-08-24）

对全部约 1.9 万行源码做一次系统性检修，原则：外部行为兼容、每步实时验证、git 全程存档。

### 结构重组
- core/db.py（622 行）→ core/db/ 包：connection（连接/事务上下文）+ schema +
  hunt_store（agents/observations/knowledge/evolve）+ tracking_store
  （任务/事件/runs/租约/批量提交协议）；包入口平面再导出，调用方零改动。
- 新增 core/coerce.py：全库唯一布尔解析三件套 parse_bool/as_bool/strict_bool，
  收编 config/evolve/privacy_guard/tracking 四处拷贝。
- config 加固：新增 update_section() 统一段落更新入口（锁内原地合并+原子落盘），
  save() 锁内快照深拷贝消除并发序列化竞态（FreqErr §15 遗留项正式关闭）。
- modules/screener.py（2238 行）→ screener/ 包：apps / traces / cleanup（含恢复）/
  machine_fp / deep_scan / fmt_reverse / guidance / common。
- modules/decompile.py（860 行）→ decompile/ 包：py_parser / pe_parser / java_parser /
  audit / common（特征库）。
- ui/gui.py（3091 行）→ gui_common.py（QSS/QThread 设施/控件工厂/共享助手）+
  ui/pages/ 包（14 个页面文件，build_pages() 按开关装配），gui.py 只剩 MainWindow 与
  launch_gui。
- ui/static/app.js（2116 行）→ core/nav/views_*/boot 八个有序加载脚本；
  切分以“拼接逐字节一致”证明零语义变更。

### 同步修复的真实缺陷
- gui._mod 闭包捕获 except 变量的潜在 NameError（FreqErr §25）。
- embedding 首跑缺索引文件误报 Err.log（同上）。

### 验证体系（新增）
- tests/ 回归套件（stdlib unittest，35 例）：coerce 矩阵、config 并发段、db 三域
  （观察 CRUD / 知识权重钳制 / tracking 批量提交暂停竞态 / 审计哈希链与脱敏）、
  decompile 危险调用与门禁、embedding dump/load 与静默回归、清理分类安全拒绝路径、
  RFC6455 握手向量。
- GUI 冒烟：QT_QPA_PLATFORM=offscreen 构建 MainWindow 全部页面并逐页切换。
- Web 冒烟：静态资源 200 + /api/ping + POST /api/<module>/<func> 真实调用。
- pyflakes 静态扫描零告警；node --check 校验全部 JS。

### 备份策略
git 仓库（每阶段一 commit）+ backups/retrace_full_*.zip 全量快照 +
backups/retrace_history.bundle（含历史的离线克隆）。
