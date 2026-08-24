# Techniques.md — 技术方案文档（实现方法与技术选型）

> 记录预估的实现方法与技术选型，随实现推进更新。

## 0. 环境事实（已探测）

- 操作系统：Windows，工作目录 `C:\Users\Amily\Desktop\最近科创\监控`
- Python 3.13.13（`winreg` 可用；scapy/pyshark 均未安装）
- Wireshark 已安装于 `C:\Program Files\Wireshark`（tshark.exe / dumpcap.exe 存在）
- 目录内现存文件：`AGENT.txt`（工作流程规范，本项目须遵守）

## 1. 依赖策略（轻量化）

| 用途 | 方案 | 依赖 |
|------|------|------|
| 抓包 | subprocess 调用 tshark（JSON 输出 `-T json`）| Wireshark 已装 |
| 注册表 | winreg | 标准库 |
| 数据库 | sqlite3 | 标准库 |
| Web 服务 | http.server + 手写 JSON API | 标准库 |
| WebSocket（扩展桥）| 自实现最小 WS 服务端（RFC6455 握手+帧）| 标准库 |
| 桌面 GUI | PyQt6（QSystemTrayIcon 托盘 / 开机自启 / PyInstaller 打包）| pip 安装 |
| Embedding | 自实现词频-哈希向量+余弦；可选 OpenAI 兼容接口 | 标准库 + AI key |
| AI 调用 | urllib 请求 OpenAI 兼容 REST | 标准库 |
| 反编译 | 自实现：dis / PE 结构解析 / class 常量池解析 | 标准库 |
| 进程/网络观察 | psutil？→ 避免：用 tasklist/netstat 等命令 + wmi 查询 | 标准库 |

原则：除 PyQt6（用户 2026-08-12 确认，满足托盘/自启/打包）外，不引入 scapy/pyshark/
requests/psutil 等大包；命令型工具优先用 `subprocess`
调用系统自带命令（tasklist、netstat、reg query 仅作补充，主路径用 winreg API）。

## 2. 各模块实现要点

### M1 pcap（tshark 封装）
- 定位 tshark：先查 PATH，再回退 `C:\Program Files\Wireshark\tshark.exe`。
- 实时抓包：`tshark -i <接口> -f <BPF过滤> -T json -l` 逐行读 stdout 解析，
  实时转事件 `packet.captured`。
- 离线分析：`tshark -r file.pcapng -T json` 批量解析。
- 提供接口枚举（`-D`）、接口流量统计（`-z io,stat`）。
- 观察目标联动（M7）：BPF 过滤目标 IP:端口，实现"只看这个 APP 的流量"。

### M2 regscan（winreg）
- 封装子树遍历（HKLM/HKCU/HKU，防权限异常的 try/except 收集继续遍历）。
- 搜索模式：路径关键词 / 值名关键词 / 值数据关键词 / 正则；另有 `mode="path"`（仅按键路径匹配，
  不匹配值名/值数据，Web"路径"选项的真实实现，不再静默降级为 contains）。
- 专项点位表：Run/RunOnce/AppInit_DLLs/服务/IFEO/Winlogon/COM InprocServer32 等，
  命中即产生 `registry.hit` 事件并打风险标记；GUI 注册表页与 Web vRegscan 均有
  「扫描自启动/COM/服务点位」入口（autostart_points）。
- 结合 M7 观察目标时，可先抓取目标安装目录相关的注册表键。

### M3 embedding
- 默认轻量：分词（拉丁/中文正则切分）→ 哈希桶计数 → L2 归一化向量，
  余弦相似度检索；文本长度用滑动窗口摘要；倒排索引加速（SQLite FTS5 可选）。
- 可选 AI 版：config 中 `embedding.provider = "openai"|"local"`，OpenAI 兼容
  embeddings 接口（如 `/v1/embeddings`），失败自动回退 local。
- 用途：经验库语义检索（"类似的漏洞我上次怎么标记的"）、观察记录聚类去重。

### M4 browser（扩展 + 中枢）
- 扩展（extension/ 目录，Manifest V3）：background.js 维持 WebSocket 连接到
  本机中枢端口；content.js 提供页面注入（可选页面：用户手动安装扩展并点选站点）。
- 能力集：DOM/JS 观察、注入脚本、请求拦截（webRequest）、存储（storage.local）
  浏览、cookie 浏览、当前站点信息上送。
- 中枢 server（自实现 RFC6455）：身份验证用扩展握手 token（config 生成），
  API 中文档化，中枢同时是 http.server 一部分（同一端口 /ws 升级）。
- 连接可靠性：MV3 service worker 空闲约 30s 即被终止，setInterval 无法在休眠期运行，
  故扩展用 chrome.alarms（0.5min，旧版 Chrome 回落 1min）定期唤醒并重连；中枢握手后
  空闲读超时 75s（明显大于 30s 心跳周期，避免两个独立计时器在阈值处竞态断链）。
- 带参数命令（activate {tabId} / observe_dom {enabled}）由 GUI/Web 专用按钮下发，
  扩展侧对缺参做守卫；popup 的 Canvas 启停要求用户显式填写 ≥12 字原因并随设置上报，
  中枢收到 canvas_guard_setting 事件时写 audit_log（与 Web/GUI 的 set_canvas_guard 并列审计）。
- 全部能力带开关：`ENABLE_BROWSER` + 扩展侧权限声明最小化。
- 相关 API Key 或私密信息需注明调用时机与审计记录（audit_log）。

### M5 evolve（自我进化）
- 输入：observations / knowledge / audit_log + 各模块命中统计。
- 操作1 规则挖掘：统计同标记类别的高频特征（关键词、注册表项、端口、API 调用），
  生成候选经验规则（阈值用户确认后写入 knowledge）。
- 操作2 权重调整：观察策略（各模块采样时长/深度）按历史命中率微调，存 config 或独立 state。
- 操作3 报告质量：观察结论与后续复证一致率统计。
- 输出：`evolve/` 下周期报告；所有自动改动均记录 diff 供人工审查（人工确认开关）。

### M6 decompile
- Python：`dis` 反汇编源码/字节码文件；AST 静态扫描（ast 库）找 eval/exec/
  importlib/反射/子进程调用等危险点，产出可疑调用清单。
  `.pyc` 字节码反编译在**受限子进程**执行（marshal.loads 反序列化不可信数据有崩溃/恶意对象
  风险）：`_PYC_EXTRACT` 脚本 + `subprocess.run([interp,"-c",...], timeout=15)` 仅回传 JSON
  字符串列表；frozen 打包态用 `shutil.which("python"/"python3")` 探测系统解释器，无则降级跳过。
- PE：自实现 PE32/PE32+ 解析（DOS 头→NT 头→节表→导入表/导出表/字符串），
  无需 pefile 包；输出导入 API（重点：网络/注册表/进程注入/加密）、可疑节名、熵估算。
- Java：自实现 .class 解析（魔数→常量池→access→字段/方法表→属性），
  提取常量池字符串、方法名与调用关系（快速版调用图）；危险清单：
  Runtime.exec、反射、反序列化 readObject、JNDI 等。
- 统一输出 JSON 结构化结果 + `decompile.done` 事件，供 M9 标记入库。

### M7 watcher（选定 APP 集中观察）
- 目标档案：exe 路径/名称/进程名 → tasklist 拿 PID。
- 轮询采集：进程树（tasklist /FO CSV 平铺 PID 表 + `wmic process get
  ProcessId,ParentProcessId /value` 建真实父子树 BFS，1.5s 缓存、失败降级仅根进程——
  绝不把全系统进程当目标）、TCP/UDP 连接（netstat -ano 按树内 PID 过滤，UDP 无状态直接收录）、
  DNS 记录（ipconfig /displaydns 快照 diff）、文件改动（目标句柄目录扫描）、
  注册表写入（与 M2 联动做基线 diff）。
- 时间线：所有采集项按时间线合成为"目标行为时间线"，Web UI 渲染。

### M8 ai（OpenAI 兼容，全局唯一 Agent）
- config：`ai.base_url / ai.api_key / ai.model / ai.timeout`；api_key 支持环境变量。
- 客户端：urllib POST `{base}/chat/completions`，SSE 流式可选（简化版先非流式）。
- 用途接口：`analyze(finding)` 风险分级、`summarize(observation)` 报告草稿、
  `extract_rules(observations)` 规则提炼、`answer(question, context)` 上下文问答。
- 统一在 ai.py 中，其余模块只 import ai 单例；未配置 key 时返回明确错误对象
  而非抛异常，保证其他模块可用。
- **不越界加固（2026-08-12）**：`SAFETY_SYS` 叠加到所有系统提示（只读顾问、
  防提示注入、禁恶意载荷、敏感脱敏）；AI 输出结构化上无执行路径，`extract_rules`
  暂未接线，`evolve` 规则写入受 `auto_apply=false` + 人工确认约束。

### M9 hunt（观察-标记-沉淀闭环）
- 主流程：`new_observation(target) → start watcher+pcap(+browser) →
  收集证据 → 生成分析卡片（AI 助力）→ 人工标记(risk/类型/结论) → 存库 →
  经验回流(规则更新提示)`。
- 观察卡片 = 结构化 JSON（时间、目标、模块证据、标记、结论、AI 摘要），
  Web UI 可回看/续写/加入经验库。
- 数据库 schema 见 Design.md，采用 snapshot 保存证据正文（mtime 防覆盖）。

## 5. M10 LLM Agent 子系统（2026-08-12 新增）

- 包结构：`modules/agent/`（__init__ 开关注册 / tools.py 工具白名单+风险分级 /
  executor.py 执行引擎 / reviewer.py 空上下文审核模型 / agent.py 主循环 / cli.py 命令行入口）。
- 主循环：`用户任务 → 主模型规划(JSON 工具调用) → 逐个 review → execute/审批 → 结果回填 → 循环`
  （max_steps 上限，全程 db.audit + Err.log）。
- reviewer：独立 chat 调用（可配 `agent.reviewer_model`，空=同主模型），只输入单条调用
  JSON + 审核提示词，输出 `{"verdict":"allow|deny","reason"}`；无 API 时降级为
  read 放行 / cmd、high 一律人工审批。**Web HTTP 调用无人工通道（confirm_cb=None）时：
  cmd 被 reviewer deny/不可用即自动拒绝、high 一律自动拒绝**（默认安全，见 agent.py 头部注释）。
- 工具集：reference(经验库)、search_registry、search_files、fingerprint(哈希/PE 指纹)、
  inspect_process、leftover_scan(残留)、run_command(白名单+黑名单)、decompile、
  web_search(逐次确认)、remove_file(确认+隔离备份)、ask(向主模型提问)。
- 命令安全：argv 列表 subprocess（无 shell）、timeout、黑名单永拒、危险命令强制人工。
- 删除安全：先 `backups/quarantine/<ts>/` 复制再删，仅精确匹配检出路径。
- 配置：`config.json` 增 `agent` 段（reviewer_model/max_steps/auto_level）。

## 6. M11 筛查工作台（screener，2026-08-13 新增）

- 定位：主入口、人机协作（人类筛查/筛选/标记 + AI 只读辅助分析），非自由任务。
- `modules/screener.py`：scan_suspicious_apps（自启动点位+风险词+可疑命名词边界+路径
  expandvars 存在性）、scan_leftover（全树主 exe 缺失/原始空目录判定/双根 HKLM+HKCU
  悬空引用）、scan_fingerprints（深度≤6、≤512MB、单次流式哈希+熵、数量≤40）、
  check_file（指纹+反编译摘要，含防御缺口校验）、track_app（复用 watcher，时间线字段
  ts/type）、mark_item（写 observations）、analyze_with_ai（只读 ai.chat+审计）。
- 风险打分：高≥0.7 / 中≥0.4 / 低≥0.2；可疑命名用词边界正则 _SUS_RE。
- 前端：GUI ScreenerPage（按钮+类别/风险筛选+表格选中标记+AI 分析框，回调经
  QMetaObject.invokeMethod 回 GUI 线程）；Web vScreener（同功能）+ vSettings 增 AI 配置
  （config.save_ai API，白名单+审计）。
- 工具复用：fingerprint 经 modules.agent.executor 调用（参数白名单过滤+审计）。

## 7. 错误自动存错机制

- logger.py 内建 `except_hook`：未捕获异常写 `Err.log`（含时间/模块/堆栈）；
- 各模块 try/except 中捕获的运行时错误也统一走 `record_err()`；
- 修复流程遵循 AGENT.txt：先读 Err.log → 修复 → 清空。

## 7b. Web API 方法语义与严格参数（2026-08-16）

- `/api/v1/tasks` 集合路由只允许 GET（列表）/POST（创建），PUT/DELETE 等其它方法
  映射 405（`_MethodNotAllowed` 异常）；已知子资源（events/runs/start/pause/update/delete/
  analyze）方法不匹配同样 405，未知路由 400。
- 外部布尔参数统一严格解析 `_strict_bool`（evolve.auto_apply、privacy_guard 的 network/
  clipboard/enabled、config 开关、web db 分支等），拒绝 `bool("false")==True` 式的字符串误判。
- Web RPC（/api/<module>/<func>）的业务失败封套为 HTTP 200 + {"ok":false,...}（前端 bizFail
  判定）；只有 v1 REST 路径才用 400/403/405/413 状态码。db 删除/停用分支对非数字 id 返回
  友好中文错误而非 Python 原生 ValueError 文本。
- 前端 run() 契约：回调 return r（或先 bizFail 检查再返回摘要）；字符串返回值作为动态状态文案；
  undefined 视为用户取消（"已取消"），避免 confirm 取消被误报失败。

## 8. GUI 线程模型（2026-08-13 修复，PyQt6 实测）

- **Worker 必须持有强引用**：`_run_async` 中 `w = _Worker(fn, args, kwargs)` 若为函数局部
  变量，函数返回后被 Python GC，`thread.started.connect(w.run)` 连接静默失效（worker 永不
  执行、回调不触发）。修复：`thread._w = w` 将 Worker 挂到 QThread 上持有。
- **跨线程回调中继**：`QMetaObject.invokeMethod(obj, callable, ...)` 的 callable 形式在
  PyQt6 下静默失效；改用模块级 `_Invoker(QObject)` + `pyqtSignal(object)` +
  QueuedConnection，worker 线程 emit、主线程执行 fn。
- **页面预加载惰性化**：PcapPage/BrowserPage/AiPage/HuntPage 由 `__init__` 自动
  `refresh()`/`load_ifaces()`（构造即启线程）改为 `showEvent` + `_loaded` 标志首次显示时
  加载；避免无事件循环环境退出时 "QThread: Destroyed while thread is still running" 崩溃。
- **测试脚本退出**：offscreen 测试中退出前应 `for t in owner._threads: t.wait(3000)` 收尾。

## 9. 完整项目查修要点（2026-08-13，全部实测）

- **db.update_observation 字段白名单**：若 allowed 集合缺字段（如 evidence），调用方静默丢弃——
  扩字段时须检查序列化（evidence 需 json.dumps）。
- **os.walk 内勿覆盖外层目录变量**：`base = f.lower()` 会破坏 `root[len(base):]` 深度计算。
- **前端 `table()` 返回 div 而非 table**：点击行绑定须 `t.querySelector("table").rows`。
- **subprocess 子命令级校验**：命令白名单只拦 argv[0] 不够，需对 ipconfig/tshark/reg 等
  白名单命令做参数级防护（`/flushdns`、`-w` 等）。
- **WebSocket token 必须持久化**：随机 token 每次启动重生成会使扩展失联，写回 config 并记审计。
- **_host_ok IPv6 字面量**：`[::1]:8080` 需取 `[...]` 内内容；`strip("[]")` 会误伤冒号。
- **Windows 命令输出中英文差异**：`ipconfig /displaydns` 用"记录名称"/"Record Name"行内冒号
  解析，勿取下一行（下一行是记录类型）。
- **Web 静态目录判定**：`startswith` 有前缀兄弟目录逃逸，用 `os.path.commonpath` 相等判断。

## 10. 前端视觉优化（2026-08-13）

### PyQt6 GUI QSS 主题
- 色板与 Web 控制台统一：`#0b0f17`（底）/`#111722`（侧栏）/`#151c28`（卡片）/`#2dd4bf`（强调）/`#283449`（边框）。
- QSS 覆盖：QMainWindow/QListWidget(导航)/QGroupBox(卡片)/QPushButton(主/次)/QLineEdit/QComboBox/
  QSpinBox/QTableWidget/QHeaderView/QPlainTextEdit/QCheckBox/QScrollBar/QSplitter。
- 侧栏重构：QWidget 容器（objectName=sidebar）+ 品牌头（QLabel brand-name/brand-sub）+
  QListWidget(objectName=navlist, 透明底/圆角项/选中态高亮) + 底部状态点。
- 页面卡片化：各页面用 QGroupBox 作卡片容器，QVBoxLayout 统一 margins=16/spacing=10；
  页头标题用 QLabel(objectName=page-title) + tag 标签。
- 主操作按钮：setObjectName("primary") 获得青色实底高亮。

### Web 控制台精修
- CSS：微调间距、滚动条、动画曲线；保持既有暗色主题不变。
- JS：整理 helper 命名与结构一致性，不改变 API 调用逻辑。

### tray.py 图标
- 放大镜图标增加抗锯齿描边与手柄渐变，高分辨率渲染。

## 4. 验收与演示路径

1. `python main.py` 启动 → Web 控制台
2. M1：选择接口→ 抓包实时显示
3. M2：关键词搜索注册表 → 命中列表
4. M6：选择目标文件（py/exe/class）→ 反编译报告
5. M7：选定目标 APP → 行为时间线
6. M9：标记观察 → 经验库检索
7. M8：配置 key 后问答/报告草稿（未配 key 时界面明确提示）
8. Eclipse：模块开关关闭某模块 → UI 隐藏对应入口

## 11. 本轮统一任务/守护进程/审计实现方案（2026-08-13）

- SQLite 增量迁移创建 `tracking_tasks`、`tracking_events`、`task_runs`，并扩展 `audit_log`；
  迁移保持现有表与 API 可用，不清空用户数据。
- `core/audit.py` 负责字段脱敏、稳定 JSON、SHA-256 hash chain、查询与链验证；业务代码不再把
  未脱敏参数直接拼接到审计字符串。
- `modules/tracking.py` 提供唯一 service facade：create/list/get/update/start/pause/delete、
  events、daemon status、AI summary。内部 daemon 使用 Event 可中断等待、线程锁保护调度状态，
  每轮为任务创建 run 记录并持久化异常。
- watcher 增加按目标执行一次的结构化采集接口；tracking daemon 调用此接口并对事件做指纹去重、
  计数聚合与保留上限控制。旧 watcher API 保持兼容。
- Web API 以 `/api/v1/tasks...` 暴露 REST 路由，同时保留原模块 RPC；统一响应 envelope、request_id、
  错误码、安全头和参数校验。
- PyQt 新增任务追踪页，直接调用 tracking facade；HTML 新增同等任务工作台并轮询状态，字段与
  后端结构一一对应。
- `main.py --daemon` 启动无界面常驻；正常 GUI/Web 启动同样注册 daemon。任务 enabled 状态决定
  下次启动是否自动恢复。
- 验证覆盖数据库迁移、任务生命周期、事件去重、审计脱敏/链完整性、API 安全与两种 UI 导入兼容。

## 12. 注册表 / DNS / 全路径文件归因方案（2026-08-14）

- `wevtutil gli` 探测 `Microsoft-Windows-Sysmon/Operational` 与 `Security` 日志，不改变系统配置。
- Sysmon XML：读取事件 11（FileCreate）、12/13/14（Registry）、22（DNS Query），提取
  EventRecordID、ProcessId、Image、TargetFilename/TargetObject/QueryName，按任务 exe/PID 严格过滤。
- Security XML：读取事件 4663，提取 ProcessName、ObjectType、ObjectName、AccessList/AccessMask，
  作为文件与注册表精确归因的系统审计兜底。
- 解析使用标准库 `xml.etree.ElementTree`；日志命令使用 argv、无 shell、超时、数量上限，事件正文截断。
- DNS 缓存差分仅在没有精确 DNS provider 时启用，标为 `correlated`；注册表关联基线只扫描目标名称/
  exe 路径命中的现有项并比较变化，同样标为 `correlated`。
- `tracking.capabilities()` 暴露 provider 状态，HTML/PyQt 任务页显示“精确/关联推断”能力摘要。
- 测试用固定 XML fixture 覆盖 Sysmon/Security 解析、目标过滤、RecordID 检查点和置信度标记。
- Security 4663 的 `AccessMask` 按注册表 KEY 权限位解析：QueryValue、EnumerateSubKeys 归为读取，
  SetValue、CreateSubKey 归为写入，DELETE 归为删除；保留原始 AccessList/AccessMask 供复核。
- 能力探测区分 channel 存在、可读取、近期确有目标事件三层状态；仅“可读取”不能宣称已经具备精确
  读取证据。日志查询失败不推进 RecordID 检查点，并生成采集器降级告警。
- 相关注册表快照只持久化脱敏预览与 SHA-256，不保存无限长原值；设置节点数和时间预算并报告截断。

## 13. Privacy Guard 技术方案（2026-08-14）

- 新增 `modules/privacy_guard.py`：能力探测、敏感规则、任务访问报告、事件标注、Sandbox 预览、注册表
  授权范围与中央 system effect gate；不生成可被误用于驱动覆盖的随机 MAC 值。
- Sandbox 计划绑定 EXE SHA-256 与依赖目录 manifest；目录限 5000 文件/2 GiB 并拒绝 junction/reparse。
  执行时重验后复制到限制 ACL 的专用 staging，再只读映射到 `C:\ReTraceSource`；vGPU、网络、
  剪贴板、音视频、打印默认 Disable。staging 只授予 Administrators/SYSTEM，并在 Sandbox 生命周期内
  持有拒绝写共享的文件句柄；复制后再次逐文件哈希。文件名拒绝 cmd 元字符。
  profile 明确 `mode=strong_isolation_no_guest_telemetry`，不把宿主日志当作 guest 内审计。
- plan token 与 approval capability 均用 `secrets.token_urlsafe`、内存锁、10 分钟 TTL；Agent 工具集只有
  `privacy_plan`。HTML 与 PyQt 都是人工审批面：HTML 在浏览器 confirm() 对话框 + 明确原因 + 确认短语
  后走 plan→approve→execute 生成一次性批准能力，中央 execute 只消费一次；确认短语是轻量一致性校验
  （非机密），真正的人工门槛是用户主动点击确认并复核原因。
- 注册表首版仅支持已登记的 `HKCU\Software\厂商\产品` 子树，登记记录绑定 task_id、EXE 路径/SHA-256、
  厂商与人工所有权说明；HKLM 及 Classes/COM/Policies/Run/App Paths/协议/系统身份项确定性拒绝。
- 计划保存 64 位视图与值状态摘要；开始执行和备份完成后在已打开 key 上两次重验，固定顺序为
  `Checkpoint-Computer` → DPAPI 加密精确单值恢复材料（30 天）→ 单值 winreg 操作 → 回读验证；
  失败恢复变更前精确值，不明文导出整个父子树。
- Tracking 在活动事件落库前调用 privacy rule matcher，派生独立告警并保留原 provider/confidence。
- Agent 的 cmd/high 工具强制 `reason` 参数；executor 在 reviewer 前后均检查，审核弹窗完整显示原因。
- 浏览器 Canvas guard 按顶级站点 allowlist 注入 MAIN world，私密 salt 与顶级 origin 派生 seed，同一
  顶级站点下各 frame 使用相同扰动、跨顶级站点不同；`window.postMessage` 事件明确标为
  `correlated_untrusted` 并限频。停用后刷新页面卸载 hook。
- MAC 入口只读探测 `netsh wlan show drivers` 并打开 Windows 官方 Wi-Fi 设置；不直接调用写配置命令，
  不覆盖 NetworkAddress，明确仅限支持随机地址的 WLAN 且可能受驱动、组策略和企业 NAC 限制。
- Canvas 启停（set_canvas_guard）现已在 Web RPC 白名单，与扩展 popup 用户手势、PyQt 本地交互并列；
  同样要求明确原因（≥12 字），按顶级站点 allowlist 注入 MAIN world。

## 14. 留样扫描与批量清理方案（2026-08-14）

- screener 新增 `scan_software_traces(keyword, install_dir="")`：复用 `regscan.search(root="ALL")` 全树搜
  注册表键/值 + `autostart_points(root="ALL")` 搜自启动 + 遍历 APPDATA/LOCALAPPDATA/ProgramData 与
  可选 install_dir 中匹配关键词的目录；统一 item 带 `type`/`target`，系统身份与 `_REGISTRY_DENY` 命中标
  高风险。
- screener 新增 `cleanup_traces(items, reason="")`：**第一步强制 `privacy_guard._create_restore_point()`**
  （非管理员或失败即整体中止，绝不裸删）；随后逐项清理——file/dir 用 `shutil.move` 进
  `backups/quarantine/`，registry_value/registry_key 先记录可恢复 JSON 再 `winreg` 删除（键需递归枚举
  子键）。`match_sensitive` 命中的系统身份项与 `_REGISTRY_DENY` 确定性跳过并返回拒绝原因。
- 注册表目标编码：`HKLM\...\key|ValueName` 表示值，`HKLM\...\key` 表示键；解析器按首个段匹配
  HKLM/HKCU/HKU/HKCR。
- Web RPC 白名单增 `screener.scan_software_traces` / `screener.cleanup_traces`；app.js vScreener 增
  「留样扫描」与「勾选批量清理」；gui.py ScreenerPage 增同功能入口，均走同一 screener facade。

## 15. 反编译危险 API 的 LLM 语义审计（2026-08-15）

- 复用 `decompile.analyze(path)` 得到静态 `calls`（name/line/danger/reason/kind）与 `score`。
- 新增 `decompile.ai_audit(path)`：收集 `danger >= 0.5` 的调用（上限 30 条），构造独立审计提示词
  （系统提示复用 `ai.SAFETY_SYS` 只读顾问边界），要求逐条输出 JSON 数组：
  `{"api","verdict":"真危险|疑似误报|常规使用","reason","verify"}`。
- 用 `ai.chat(temperature=0.1, max_tokens=1500, model=agent.reviewer_model 或主模型)` 调用；
  JSON 解析失败降级为返回原始文本，不抛异常。
- `ai.configured()` 为 False 时降级：`{"ok": False, "error": "AI 未配置", "static_score": score, "review": []}`。
- 返回结构：`{"ok": True, "file", "static_score", "review": [...], "ai_text"}`；仅作增强信号，不替代静态规则。
- 前端接入：GUI DecompilePage 增「AI 审计」按钮；Web vDecompile 增同入口；web_main ALLOWED 增
  `decompile.ai_audit`。

## 14. 通用机器指纹文件扫描技术方案

### 14.1 问题背景

常规软件卸载（控制面板/设置/自带卸载程序）通常只删除安装目录和注册表卸载条目，但不会清理用户在 `%APPDATA%` / `%LOCALAPPDATA%` 中留下的**机器指纹文件**。这些文件包括：
- 设备唯一标识 UUID（如 `machineid`、`machineId`、`Client ID`）
- 设备身份配置（如 Qoder 的 `DIPS`）
- 认证令牌（如 `auth.json`、`auth-tokens.dat`）
- 共享持久化存储（如 `SharedStorage`、`blob_storage`）
- 遥测/状态文件（如 `Local State`、`storage.json`）

这些指纹文件可用于跨会话追踪用户、关联多设备身份、或在重新安装后恢复旧身份。

### 14.2 指纹模式数据库设计

```python
FINGERPRINT_FILE_PATTERNS = [
    {"vendor": "Alibaba Cloud", "product": "Qoder", "dir": "Qoder",
     "file": "machineid", "desc": "...", "risk": "高", "category": "fingerprint"},
    # ... 覆盖 Qoder/Cursor/Windsurf/Aider/Cline/Copilot/Chrome/Edge/VSCode 等
]
```

- `dir`：`%APPDATA%` 或 `%LOCALAPPDATA%` 下的子目录，支持多级（如 `Google\Chrome\User Data`）
- `file`：文件名或目录名（`blob_storage` 是目录型目标）
- `category`：`fingerprint`（设备标识）/ `token`（认证令牌）/ `state`（状态文件）/ `storage`（持久化存储）
- `risk`：高/中/低

### 14.3 扫描算法

1. 获取扫描根目录：`_user_scan_dirs()` 返回 `[%APPDATA%, %LOCALAPPDATA%, %PROGRAMDATA%]`
2. 遍历每个根目录的一级子目录
3. 对每个子目录，匹配 `FINGERPRINT_FILE_PATTERNS` 中 `dir` 的第一级
4. 对命中的模式，拼接完整路径（处理多级子目录）
5. 检查目标文件/目录是否存在（支持 glob 变体匹配）
6. 小文件（≤4KB）读取前 64 字节作为预览
7. 按 keyword 过滤（vendor/product/desc/category 子串匹配）
8. 返回统一格式的 items 列表

### 14.4 前端接入

- Web 控制台 `vScreener` 新增「④ 机器指纹文件扫描」卡片
- 输入框：关键词过滤（留空=全部）
- 按钮：`scan_machine_fingerprints`
- 输出：表格展示（名称、路径、风险、大小、修改时间、预览）

### 14.5 与现有扫描的关系

| 扫描函数 | 覆盖范围 | 匹配方式 |
|---------|---------|---------|
| `scan_suspicious_apps` | 自启动点位 | 注册表关键词 |
| `scan_leftover` | 残留目录/悬空引用 | 路径存在性 |
| `scan_fingerprints` | exe/dll 哈希/熵 | 文件内容分析 |
| `scan_software_traces` | 注册表全树+自启动+卸载+文件系统 | 关键词下钻 |
| `scan_machine_fingerprints` | 已知软件指纹文件 | 模式精确匹配 |
| `scan_generic_fingerprints` | 未知软件指纹文件 | 文件名关键词+UUID 内容 |
| `scan_prefetch_traces` | Prefetch 执行痕迹 | 关键词匹配 .pf 文件名 |
| `scan_usage_history` | MuiCache/UserAssist/AppCompat/BAM | 关键词匹配注册表值 |
| `scan_wer_traces` | WER 崩溃报告 | 关键词匹配报告目录名 |

### 14.6 通用指纹内容检测（`scan_generic_fingerprints`）

- **双证据判定**（任一命中即列为候选）：
  1. 文件名命中标识类正则 `_ID_NAME_RE`（machine-id/device-id/client-id/app-id/anon-id/fingerprint/telemetry-id/hwid/uuid 等，带词边界）
  2. 内容判定 `_looks_like_identifier`：文件 ≤256 字节，内容去空白后为 UUID（`_UUID_RE` 8-4-4-4-12）或 32-64 位十六进制串（`_HEXID_RE`）
- **资源护栏**：深度 ≤3 级、每目录文件 ≤300、每目录子项 ≤50、命中上限 `_MAX_GENERIC_SCAN=30`
- **实测案例**：发现 `C:\ProgramData\aliyun\vminit\PWD_UUID`（云平台 VM 初始化写入的机器 UUID，36 字节），不在任何已知模式库中

### 14.7 深潜扫描实现要点

- **Prefetch**：`C:\Windows\Prefetch\<EXE>-<HASH8>.pf`；.pf 头部含 UTF-16LE 完整执行路径，用两个正则兜底还原（先 `[A-Za-z]:\\(?:[^\x00]{1,200}\\)*[^\x00]{1,120}\.exe` 匹配正常路径，失败再用去 NUL 字节后的宽松模式）。系统禁用 Prefetch 时目录为空，如实返回空列表而非报错。
- **MuiCache**：`HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`，值名即 exe 完整路径，值为 FriendlyName。
- **UserAssist**：`HKCU\...\Explorer\UserAssist\<GUID>\Count`，值名为 **ROT13 编码**的路径（`_rot13` 仅翻转字母），值数据为运行计数+最后运行时间。
- **AppCompatFlags**：`HKCU\...\AppCompatFlags\Compatibility Assistant\Store`，值名即程序路径。
- **BAM**：`HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>`，值名为 `\Device\HarddiskVolumeX\...` 原生路径，值数据前 8 字节为 FILETIME（`(ft - 116444736000000000) // 10000000` 转 Unix 秒）。需管理员可读，不可读时静默跳过（不吞其余源）。实测找到 Qoder.exe 最后执行时间戳。
- **WER**：`%LOCALAPPDATA%\Microsoft\Windows\WER` 与 `%PROGRAMDATA%\Microsoft\Windows\WER` 的 ReportArchive/ReportQueue，目录命名 `<应用名>_<版本>_<哈希>`。
- **统一降级策略**：四个子源任一不可读/不存在均 try/except 跳过并保留其余源结果；keyword 为空时返回可读 error 提示（与 scan_software_traces 一致）。

## 15. 指纹编码格式逆向技术方案

### 15.1 格式识别级联（analyze_fingerprint_format）

1. **SQLite**：读前 16 字节 `SQLite format 3\x00` → 只读连接（`file:...?mode=ro` URI）列 sqlite_master 表与 PRAGMA table_info 列；`_ID_HINT_RE` 判定身份列；`-wal/-shm` 侧车检测。
2. **JSON**：UTF-8 严格解码后 `json.loads` 成功且为 dict → `_walk_json` 递归（深度 ≤8，数组 ≤20 元素），`_parse_leaf` 分类叶子值。
3. **DPAPI**：整体内容 base64 解码后前 40 字节内搜 magic `\x01\x00\x00\x00\xd0\x8c\x9d\xdf`（兼容 "DPAPI\x01" ASCII 前缀偏移 5 的变体）。
4. **uuid_text**：整文 strip 后匹配 `_UUID_FULL_RE`（8-4-4-4-12 十六进制）。
5. **hex_uuid**：strip 后去连字符恰 32 字符且全 hex。
6. **binary**：以上都不中（UTF-8 严格解码失败即二进制）。

### 15.2 叶子值语义分类（_parse_leaf）

| kind | 判据 | 替换值生成 |
|------|------|-----------|
| uuid | `_UUID_FULL_RE` | `uuid.uuid4()` 字符串 |
| hex32 | `^[0-9a-f]{32}$` | `uuid4().hex` |
| hex64 | `^[0-9a-f]{64}$` | `sha256(uuid4().bytes)` |
| hex_uuid | 去连字符后 32 hex | `uuid4().hex` |
| dpapi_blob | base64 解码前 40 字节含 DPAPI magic | 无（不可伪造） |
| unix_timestamp | int 或 10 位数字字符串，值域 946684800~4102444800 | 无（不影响身份） |
| unix_timestamp_ms | 13 位同值域×1000 | 无 |
| hex | ≥24 全 hex | `secrets.token_hex(n/2)[:n]` 保持原长 |
| numeric_string / string / bool / number | 兜底 | 无 |

### 15.3 自洽性保证

- 生成值必须再次通过同一格式校验（`_verify_fmt.py` 断言"替换值符合创建规则"）——防止出现"工具自己生成的替换值反而被软件判损坏"的矛盾。
- 敏感字段值预览截断（dpapi 只显示长度；uuid/hex 只显示前 12 字符）。

### 15.4 关键实测数据（Qoder 2026-08-23）

| 文件 | 格式 | 身份字段 |
|------|------|---------|
| machineid | uuid_text | UUID v4 `950d5322-...` |
| SharedClientCache\cache\id | uuid_text | UUID `64343263-...` |
| Local State | json | os_crypt.encrypted_key=dpapi_blob；installation_date2=unix_timestamp |
| Preferences | json | electron.media.device_id_salt=hex32 |
| DIPS | sqlite | meta/config/bounces/popups 4 表（Chrome DIPS 弹窗跳转记录） |
| SharedStorage | sqlite | 空库（仅初始化） |

## 16. 指纹修改 AI 指导技术方案

### 16.1 三层安全防线

**第一层：确定性前置检查**（`fingerprint_guidance` 入口，代码层）
- `_fp_guidance_pre_check(path)`：受保护路径（`_is_protected_fs_path`）拒绝；文件不存在拒绝；运行中 exe（`tasklist /FI IMAGENAME` 匹配）拒绝
- 意图关键词黑名单（`_FP_GUIDANCE_DENY_HINTS`）：付费/VIP/注册码/破解/激活码/serial key 等，命中即返回合规拒绝

**第二层：LLM 系统提示强制自检**（`_build_fp_guidance_prompt`，模型层）
- 系统提示明确要求 LLM 在回答前评估①绕过付费墙②系统损害
- 通过自检 → 开头输出【已检查】；绕过付费墙 → 拒绝并立即结束
- 硬行为边界：绝不自动执行、绝不提供绕过付费方法、写盘必须含备份→修改→验证→回滚

**第三层：【已检查】后检查**（`fingerprint_guidance` 返回前，代码层）
- 扫描返回文本是否含【已检查】标记；不含则追加"⚠️ 安全自检标记缺失"警告
- 结果中附加 `safety_check_passed: bool` 字段供前端着色

### 16.2 上下文注入

不凭空猜格式——先调用 `analyze_fingerprint_format` + `generate_trusted_fingerprint` 获取：
- 格式类型、创建规则、身份字段清单、替换值建议
- 序列化后注入系统提示的"上下文"块，LLM 基于此生成指导

### 16.3 提示词关键约束

- `prepend_safety=False`（我们自带完整安全边界，不叠加 SAFETY_SYS 避免冲突）
- 系统提示要求"用中文回答，关键风险点用 ⚠️ 标注"
- 涉及写盘必须包含：①备份原文件 ②具体命令/操作 ③回滚方法
- 涉及注册表/系统文件必须提醒创建系统还原点

## 17. Agent 工具权限分级技术方案

### 17.1 审批逻辑（agent._approve）

```python
def _approve(cb, name, args, verdict, risk):
    if risk == tools.RISK_READ:
        if verdict and verdict.get("verdict") == "deny":
            return _confirm(cb, name, args, verdict, forced=False)
        return True  # 只读自动放行
    return _confirm(cb, name, args, verdict, forced=True)  # 读写一律请示
```

### 17. 新增只读工具清单

| 工具 | 功能 | 风险 |
|------|------|------|
| scan_fingerprints | 扫描已知/未知指纹文件 | read |
| scan_software_traces | 留样扫描（注册表+自启动+卸载+FS） | read |
| analyze_fingerprint_format | 逆向指纹编码格式 | read |
| generate_trusted_fingerprint | 生成合法替换值预览 | read |
| scan_prefetch_traces | Prefetch 执行痕迹 | read |
| scan_usage_history | 注册表使用历史四源 | read |
| scan_wer_traces | WER 崩溃报告 | read |
| modify_fingerprint | 修改指纹为新值（备份+写盘+验证） | high |

### 17.3 modify_fingerprint 写盘安全

1. 受保护路径拒绝（`_is_protected_fs_path`）
2. 备份到 `backups/quarantine/<ts>/`
3. 写盘（UTF-8 文本）
4. 回读验证 `written == new_value`
5. 返回备份路径供回滚

### 17.4 人工通道

- **CLI**：`cli.py` `_confirm` → `input("放行执行? [y/N]")`
- **GUI**：`AiHelperPage._confirm` → `QMessageBox.question`（高危弹"[高危·必须人工审批]"）
- **Web**：暂无人工通道 → `confirm_cb=None` → 读写一律自动拒绝（默认安全）
