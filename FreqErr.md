# FreqErr.md — 常见错误类型记录

## 1. 工具落盘不一致（本次出现，谨防复发）
- 现象：SearchReplace 返回"已应用"的 diff，但文件实际未变（多批编辑中部分丢失，如 gui.py 的 "ui" 开关移除、_run_async 窗口锚定、app.js pcap try/finally）。
- 处置：任何关键修改后用 Grep/Read 复核落盘；若 SearchReplace 不可靠，改用命令行 python 脚本替换（本项目已用 `python -c`/临时脚本成功）。
- 教训：批处理多条 SearchReplace 到同一文件后，必须逐项 grep 验证。

## 2. PowerShell 引号转义
- 现象：`python -c "..."` 内含双引号/括号时被 PowerShell 截断报 SyntaxError。
- 处置：复杂逻辑写临时 `.py` 脚本执行，用完即删；或使用不含引号的表达式。

## 3. PyQt6 环境警告（非错误）
- QFontDatabase offscreen 字体缺失、propagateSizeHints 提示：仅 offscreen 测试平台出现，不影响真实桌面运行。

## 4. QThread 生命周期三连坑（2026-08-13 实测，谨防复发）
- [Worker 被 GC] `_run_async` 中 Worker 实例若为函数局部变量，函数返回后 Python GC 销毁它，
  `thread.started.connect(w.run)` 连接静默失效（worker 永不执行、回调不触发）。正确做法：
  在 QThread 上持有强引用 `thread._w = w`。
- [跨线程调用静默失效] `QMetaObject.invokeMethod(obj, 闭包/普通函数, QueuedConnection)` 在
  PyQt6 下不执行且无报错；`thread.quit` 经 AutoConnection 会转 QueuedConnection 依赖主循环。
  正确做法：模块级 `_Invoker(QObject)` + `pyqtSignal(object)` + QueuedConnection 中继
  （worker 线程 emit，主线程槽执行）。
- [退出时 QThread 仍运行] 页面构造即 `refresh()`/`load_ifaces()` 会在无事件循环环境退出时触发
  "QThread: Destroyed while thread is still running" 崩溃；已完成任务的线程若被 deleteLater
  后又从锚定列表遍历 isRunning/wait 会抛 RuntimeError。正确做法：页面预加载一律 showEvent 惰性
  （_loaded 标志）；finished 时从锚定列表移除并释放 Worker 引用；遍历线程包 try/except RuntimeError。

## 5. 完整查修新增常见错误（2026-08-13）
- [字段白名单静默丢弃] `update_observation` 等函数有 allowed 字段集合，缺字段时调用方参数被
  静默丢弃（evidence 曾整块丢失）。正确做法：扩字段时同步补序列化（list→json.dumps）并测试读回。
- [os.walk 变量覆盖] 循环内 `base = f.lower()` 覆盖外层目录变量，破坏深度计算。正确做法：
  用独立变量名（fname）。
- [前端 div vs table] `table()` 返回 wrap div，`div.rows` 是 undefined。正确做法：
  `wrap.querySelector("table").rows`。
- [命令白名单只查 argv[0]] `ipconfig /flushdns`/`tshark -w` 等副作用子命令逃逸。正确做法：
  对白名单命令做参数级防护（仅允许查询类/禁写文件参数）。
- [验证断言用英文子串] 中文错误消息不含 "error" 字样，`"error" in msg` 恒 False。正确做法：
  `bool(r.get("error"))` 或 `r.get("error") is not None`。

## 6. 前端拼接括号导致整页白屏（2026-08-13）
- [JS 语法错误未被 API 冒烟覆盖] 动态 UI 大段 `appendChild(card(row(btn(...))))` 少一个右括号时，
  Python/API 测试仍全绿，但浏览器整个 `app.js` 不执行、导航为空。正确做法：每轮 Web 改动强制执行
  Node `--check ui/static/app.js`，并用真实浏览器读取 console + 点击新增页面。

## 7. try/except 中间插入逻辑导致语法结构破坏（2026-08-13）
- [补丁落点错误] 在 `except OverflowError` 与后续 `except Exception` 之间插入普通 `if`，会使第二个
  except 失去紧邻 try 的语法关系。正确做法：异常分支全部连续结束后再插入业务校验，并在每次补丁后
  立即运行 `py_compile`，不要等到批量修改完成。

## 8. 长期事件追踪的断点、降级与保留陷阱（2026-08-14）
- [先推进 checkpoint 再截断返回] 会让尾部事件永久丢失。正确做法：不截断已采事件，Event Log 按
  RecordID 顺序分页；仅在事件和 checkpoint 同一事务提交成功后推进。
- [通道可读即宣称精确] 会把空日志/历史配置误报为当前能力。正确做法：区分 present/readable/
  recent-observed，按事件类型和 AccessMask 分别声明读/写能力，fallback 保持 correlated 可见。
- [截断快照当完整快照比较] 会产生批量假删除/假新增。正确做法：truncated 时禁止删除判断，并把
  已扫描结果合并到旧基线。
- [直接切片 JSON 字符串] 会产生非法 JSON，随后丢失 confidence。正确做法：先结构化保留归因字段、
  标注 payload_truncated，再完整编码；UI 对缺失置信度默认 unknown。
- [旧 worker 只检查 enabled] 在租约换主后仍可回写旧 checkpoint。正确做法：原子提交同时校验
  daemon lease owner/heartbeat；积压时只续采 Event Log，不重复昂贵快照。

## 9. 隐私保护的错误安全承诺与授权边界（2026-08-14）

- [把宿主日志当沙箱遥测] guest 内访问不会出现在宿主时间线；固定写“强隔离、无 guest 内部遥测”。
- [固定短语不等于人工批准] 硬编码确认短语（"我已审查并批准"）可被 Agent/HTTP 客户端自动重放，不能
  当作机密或唯一门槛。2026-08-15 用户确认 Web 同为审批面后，Web 的 plan→approve→execute 已开放；
  真正的人工门槛是用户主动点击 confirm() 对话框 + 复核 ≥12 字原因，确认短语仅作轻量一致性校验。
  跨站/跨源仍由 X-ReTrace 头 + Host/Origin 白名单阻断。
- [近期访问等于 APP 所有权] HKLM 默认拒绝；HKCU 也须登记精确厂商/产品子树并绑定 APP SHA-256。
- [恢复材料等于事务] 还原点/reg export 不是事务；须双次重验、写后回读、失败值级回滚和备份 ACL。
- [origin 稳定 Canvas 噪声防跨站] 应按“私密 salt + 顶级站点”派生 seed，页面事件仅算不可信关联。

## 10. 全量检修新增常见错误（2026-08-15）

- [跨模块函数返回类型误用] `regscan.search` 返回 dict（`{"hits":[...]}`），但 `agent.tools._search_registry`
  直接 `len(rows)` 把它当 list，得到的是 dict 键数而非命中数。正确做法：`rows = res.get("hits", [])
  if isinstance(res, dict) else []`。跨模块调用前先确认返回约定，勿假设类型。
- [GUI 设置页开关漏项] SettingsPage 的模块开关元组漏 `privacy_guard`，而 MainWindow 用
  `config.enabled("privacy_guard")` 注册页面，导致该开关无法从 GUI 管理。正确做法：config.switches /
  modules.MODULES / GUI 页面注册 / GUI 设置页开关 / Web 视图注册 五处必须同步新增模块。
- [JS 语法错误复发致白屏] 留样扫描任务拼接 `card(row(btn(...)))` 少一个右括号，node --check 报
  `missing ) after argument list`，但 Python/API 冒烟全绿。正确做法：每次 Web 改动后必须 `node --check`
  校验（见 FreqErr #6），且 node 检查必须带 `encoding="utf-8"` 避免 GBK 解码崩溃掩盖真实语法错误。
- [subprocess 默认编码] `subprocess.run(text=True)` 在中文 Windows 用 GBK 解码，子进程输出 UTF-8 中文
  时报 UnicodeDecodeError。正确做法：显式 `encoding="utf-8", errors="replace"`。

## 11. 缺漏补齐新增常见错误（2026-08-15）

- [GUI 页面引用未定义 self.status] WatcherPage 的 `remove()` 回调调用 `_set_status(self.status,...)`，
  但该页面 __init__ 从未定义 `self.status`（其它页面有，唯独它漏了）→ 点击删除目标必现 AttributeError，
  且被 `_Invoker` 的 except 静默吞掉。正确做法：新增按钮回调前，先确认页面所有被回调引用的属性/控件
  都在 __init__ 中初始化；用子 AGENT 逐页面比对同类模式。
- [删除类回调返回类型误判] `watcher.remove_target` 返回纯 `bool`，但 GUI 回调按
  `isinstance(r,(tuple,list)) and r[0]` 判断（add_target 返回元组，两者契约不同）→ 删除成功也显示"失败"。
  正确做法：跨模块调用前核对返回约定；bool 用 `bool(r)` 判断，tuple 才用下标判断。
- [前端假成功] Web `api()` 只在 HTTP/ok 失败时抛错，`remove_target` 目标不存在返回 `False` 且 `ok=True`，
  前端照样显示"已删除" → 假成功。正确做法：删除类 API 必须检查返回布尔，`if(!ok) throw` 后再提示成功。
- [布尔字符串被误转] `bool("false")==True`。手造 JSON 请求传 `ai_enabled:"false"` 会被静默反转为"启用"。
  正确做法：严格布尔解析 `_to_bool`（仅接受 bool/0-1/"true"/"false" 等），拒绝其它值抛 400。
- [API 路由吞并非数字段] `_v1` 路由 `len(parts)>=4 and parts[:3]==["api","v1","tasks"]` 对
  `/api/v1/tasks/create` 也命中，`int("create")` 抛 ValueError 泄露内部异常。正确做法：分支条件加
  `and parts[3].isdigit()`，非数字段统一走"未知 API 路由"。
- [删除 id=0 假成功] 桌面端 `delete_observation(0)`/`delete_knowledge(0)` 直接透传 db 层无校验，
  `DELETE WHERE id=0` 无效果但界面显示"完成"。正确做法：删除/停用函数在数据层统一加 `id<=0` 拒绝，
  双入口（GUI/Web）共同防护，不在 UI 层各管各的。

## 12. AI 语义审计新增常见错误（2026-08-15）

- [解析失败被误判为"无高危调用"（假阴性）] 函数只检查返回结果的顶层 `"error"`，忽略了嵌套在
  `info` 里的 `error`/`parse_error`/`truncated_sections`/`parse_warn` 等"非致命但结果不可靠"标志，
  导致损坏 PE/乱码源码/截断文件被报告为"干净"。正确做法：消费解析结果前，逐层检查 error + 解析
  警告标志，命中即判失败或显式标注"解析不完整"，绝不宣称"无高危"。
- [模块开关被内部 import 绕过] 新增函数内部 `from modules import ai` 并调用 `ai.chat`，但未检查
  `config.enabled("ai")`，关闭 ai 开关后仍会发真实 LLM 请求。正确做法：任何跨模块能力调用前，
  在调用侧先查目标模块开关（不能只依赖 Web 层对当前模块的门禁）。
- [业务层 ok 与 HTTP 层 ok 混淆] 后端业务函数返回 `{"ok": False, "error": "AI 未配置"}`，Web 层
  把整个 dict 包进 HTTP `{"ok": True, "data": ...}`，前端 `api()` 只看 HTTP ok 不抛错，UI 用
  `run()` 把"未配置"也显示成绿色成功。正确做法：前端对业务 `r.ok === false` 显式 throw（走红字
  错误路径），或 run() 支持业务失败态。

## 13. PE 导入表解析常见错误（2026-08-15）

- [结构体字段错位] `IMAGE_IMPORT_DESCRIPTOR` 是 5 个 DWORD（含 ForwarderChain），若用
  `struct.unpack_from("<IIII", ...)` 只解 4 个，会把 ForwarderChain 当 Name、Name 当 FirstThunk，
  导致 DLL 名全变 `(hidden)`、函数名读不出。正确做法：`"<IIIII"` 解满 5 个 DWORD。
- [IMAGE_IMPORT_BY_NAME 未跳过 Hint] 函数名 RVA 指向的是 `WORD Hint + NUL 结尾 Name`，若从
  Hint 开始 `_cstr` 读，第一个字节是 Hint 低字节、第二个是 0x00，读到 1 字符乱码就断。正确做法：
  `name_off + 2` 跳过 2 字节 Hint 再读字符串。
- [延迟导入表漏解析] DataDirectory 第 13 项（`dd_off + 104`）是 Delayed Import Directory，
  恶意样本常用延迟加载规避静态分析（把高危 API 藏进去）。只解析标准导入表会漏报。正确做法：
  读 delay_rva，按 32 字节 `IMAGE_DELAYLOAD_DESCRIPTOR` 循环（grAttrs bit0=0 时是 VA 需减
  image_base 转 RVA），thunk 复用同一解析函数。
- [按序号导入被丢弃] `val & (1<<63|1<<31)` 为真表示按序号导入（无函数名），若直接跳过会漏报
  按序号导入的危险 API。正确做法：记录为 `#ordinal` 并标低置信，至少不静默丢弃。

## 14. 全量查修新增常见错误（2026-08-15）

- [SQLite rowcount 幂等语义] `UPDATE ... SET enabled=?` 的 `cur.rowcount` 只统计**值实际变化**的行，
  目标行已处于相同值时返回 0。若据此判断"是否存在"会误报"目标不存在"。正确做法：删除类用 rowcount
  判断存在；更新类先用 `SELECT 1 WHERE id=?` 校验存在，再执行 UPDATE，返回"是否存在"而非"是否变更"。
- [删除/停用返回 lastrowid 恒 0] `DELETE`/`UPDATE` 语句经 `_exec()` 返回 `cur.lastrowid` 恒为 0，
  调用方无法区分"删除成功"与"id 不存在"，GUI 一律显示"完成"→假成功。正确做法：删除/停用返回
  `rowcount > 0` 或先查存在，双入口（GUI/Web）共同按返回值判定。
- [后台线程 stop 后状态未复位致无法重启] watcher `stop()` 把 state 置 `"stopped"` 而 `start()` 只接受
  `"idle"`，导致停止后无法再次启动。正确做法：`stop()` 后 state 复位 `"idle"`；`start()` 再补
  `thread.is_alive()` 判断防旧线程未退时双采集。
- [跨模块返回 dict 但 GUI 当 list 用] `regscan.search` 返回 `{hits:[...]}`，GUI 回调直接 `_fill_table(rows)`
  （只接受 list）导致表格永远走错误分支显示原始 JSON。正确做法：GUI 侧先 `rows.get("hits", [])`，
  与 Web 端 `r.hits` 取法对齐（跨模块调用前确认返回约定）。
- [配置 section 返回非 dict] config.json 某 section 为 null/字符串时 `section()` 原样返回非 dict，
  调用方 `sec.get(...)` 直接 AttributeError。正确做法：`section()` 对非 dict 值返回 `{}` 或 default。
- [配置并发写无锁] `config.save()` 写 `.tmp` + `os.replace` 无锁，多线程（browser/web/gui）并发写会
  互相覆盖或写坏 config.json。正确做法：`save()` 的文件写段统一加 `_save_lock`。
- [WebSocket 短读误判断链] `recv(2)`/`recv(8)` 可能只读回部分字节。正确做法：封装 `recv_exact` 循环
  读满；监听 socket bind 完成后用 Event 通知 stop() 关闭，避免 start 后立即 stop 的空等/泄漏。

## 15. 全量查修（第三轮）新增常见错误（2026-08-15）

- [前端业务失败显示为成功（HTTP ok 与业务 ok 混淆，多调用点残留）] vPcap 开始抓包 / vWatcher 添加目标 /
  vDecompile 分析 / vAi 提问 / vScreener AI 分析 / vHunt 开始观察 / vRegscan 搜索等，后端业务返回
  `{ok:false}`/`[false,msg]`/`{error}` 时前端仍显示绿色成功。正确做法：`run()` 统一判定业务失败
  （bizFail/bizErr 覆盖 false / `[false,...]` / `{ok:false}` / `{error}`），非 run() 调用点单独 throw。
- [后端 tuple 返回经 JSON 序列化为数组] `pcap.start_capture`/`watcher.add_target` 返回 `(bool,msg)`，
  前端拿到的是 `[false,msg]`，须 `Array.isArray(r) && r[0]===false` 判定，不能当普通行数组取 `rows`。
- [WebSocket 错误分支元组长度不一致] `_recv_frame` 超大帧返回 2 元组，调用方 3 元组解包抛 ValueError
  被外层 except 吞掉，`opcode=="error"` 分支永远不可达。正确做法：错误分支也返回 3 元组。
- [离线解析 stderr 未排空死锁] `Popen(stderr=PIPE)` 后只在进程结束后读 stderr，大 stderr 写满管道缓冲
  会死锁（超时判断在阻塞读 stdout 的 for 循环内，无法生效）。正确做法：启动 daemon 线程持续读 stderr。
- [配置段/字段非法值静默失效] `cfg["watcher"]` 非 dict、interval/max_events 非法值、watch_dirs 非 list
  会 AttributeError / 逐字符迭代静默失效。正确做法：isinstance 校验 + try/except (TypeError, ValueError)
  兜底默认值。
- [config.save 深拷贝快照仍残留并发竞态（已知限制）] `deepcopy` 本身仍迭代活字典，与顶层键插入
  （browser token / save_ai / privacy_guard setdefault）并发仍可能 RuntimeError。正确做法：统一 mutation
  锁（config.mutate + RLock）。本轮以深拷贝快照 + 文档记录为折中，未做多文件重构。

## 16. 全量查修（第四轮）新增常见错误（2026-08-15）

- [marshal.loads 反序列化不可信数据] 分析工具直接 `marshal.loads` 反编译可疑 .pyc，官方明确警告
  marshal 不可用于不可信来源（可致解释器崩溃/加载恶意对象），但工具核心用途正是分析可疑文件。
  正确做法：把 marshal.loads + dis 放到受限子进程（`subprocess.run([interp, "-c", script, path])`，
  timeout 兜底），仅回传 JSON 字符串列表，主进程不持有 code 对象；子进程崩溃/超时均显式 parse_error。
- [frozen 环境 sys.executable 语义错位] PyInstaller 打包后 `sys.executable` 是应用 exe（非 Python 解释器），
  用 `[sys.executable, "-c", ...]` 会拉起第二个应用实例（多开窗口/重复绑端口），`sys._base_executable`
  在 PyInstaller 下也指向 bootloader 而非解释器。正确做法：frozen 时 `shutil.which("python"/"python3")`
  探测系统解释器，探测不到则降级跳过该能力并写 parse_error，绝不裸用 sys.executable 跑 -c。
- [WebSocket 消息负载未校验类型] `_dispatch` 直接 `data.get("event")` 后 `ev["ts"]=...`，认证客户端发
  `event:null`/字符串 时抛 TypeError/AttributeError 使连接线程崩溃（except 未覆盖）。正确做法：入口
  `isinstance(data, dict)` 校验 + 各分支字段类型校验 + 数值字段用安全转换（`try: int(v) except: 0`），
  并把 except 扩展到 TypeError/AttributeError/KeyError 兜底。
- [前端写操作假成功残留] `await api()` 后不检查业务返回直接 `setStatus(...,"ok")`，删除/登记/自启等
  写操作在后端返回 `{ok:false}`/`{error}`/`null` 时仍显示绿色成功。正确做法：所有写操作调用点统一
  检查 `bizFail(r)`（覆盖 false/[false,msg]/{ok:false}/{error}）或 `r===null/undefined`，失败 throw 走
  红字错误路径；GUI 回调同样先判 `r is None/False/dict(error)` 再提示成功。

## 17. 前端布局重构 + 遗漏视图补齐（2026-08-15 第二轮）

- [无参函数误传位置参数] `embedding.provider()` / `embedding.stats()` 等后端无参函数，GUI 端
  `_run_async(self, _mod("embedding", "provider"), cb, "_unavailable")` 把字符串当位置参数传入；
  TypeError 被 `except Exception` 静默吞掉，状态栏永远显示空。正确做法：调用前看函数签名，
  无参不传任何 args/kwargs。
- [网页前端遗漏视图——boot 未注册 + ALLOWED 与 app.js 不同步] `app.js` 的 `boot()` 只为部分模块写
  了 `vXxx` 视图函数；其余模块即使后端 ALLOWED 列入白名单，前端也无入口。正确做法：
  模块白名单扩张后必须同步 `boot()` 注册视图与 NAV；新增视图按统一模板（status → 工具卡 →
  操作卡 → 输出区）。
- [GUI 端能力漏暴露——白名单与页面按钮脱节] 后端函数经 ALLOWED 暴露但 GUI 页面没加按钮，
  例如 `privacy_guard.protected_rules` 与 `registry_scopes`。正确做法：每次给后端加可调用
  RPC，同步核查 GUI 与 Web 是否加了对应入口。
- [状态回灌依赖未定义全局变量] `preview_cleanup` / `cleanup_traces` 引用 `window.__screener_items`
  但网页从未赋值，导致永远传空 items。正确做法：用闭包局部变量存储最近一次扫描结果，传给
  下游操作，避免全局污染与 undefined。
- [_smoke 测试断言与白名单不同步] `_web_smoke.py` 中两条断言 `code == 403` 假设某些 RPC
  因不在 ALLOWED 而拒绝；白名单扩张后 HTTP 调到该 RPC 返回 200 + 业务失败。正确做法：
  ALLOWED 扩张后同步更新 `_web_smoke.py` 断言为 `(code == 200 and not j["ok"])`，
  或针对业务层拒绝添加专用 fixture。
- [子 AGENT 报告需逐项核实，不可直接采信] 子 AGENT 会基于"模式匹配"产出大量误报
  （如"H1：方法内使用未定义的 task 变量"，实际是 `task = self._selected()` 已赋值）。
  正确做法：子 AGENT 报告的真 bug 比例约 20-30%（本轮 17 项中真问题 3 项）；
  对每条 H/M 报告必须直接读目标代码核实，不可"信任"或"忽略"，建议删误报条目入
  "已核实-误报"清单留底。

## 18. 全量检修：有口没码清零（2026-08-15 第五轮）

- [前端 kwargs 参数名与后端签名错位] Web 前端 `api("m","f",{...})` 的键名与后端 `fn(**kwargs)`
  的参数名不一致时抛 TypeError，被 do_POST 的 except 兜底成 200 + `{ok:false}`，前端表现为按钮
  永远失败。正确做法：①后端 `_call` 调用前用 `inspect.signature(fn).bind(**kwargs)` 预检并返回
  "调用参数不匹配 m.f: ..." 清晰错误；②前端与后端契约用脚本逐调用点核对（见下条）。
- [批量 replace_all 漏换行变体] 同一段代码在多处出现但换行/缩进不同，`replace_all` 只命中同格式
  的那几处（本例 approve_system_action 4 处中 wifiBtn 因函数名后换行漏改）。正确做法：批量编辑后
  立即 grep 旧模式（如 `approval_text`）确认 0 残留，不要只看工具返回的"已全部替换"。
- [检测脚本按 (module,func) 去重掩盖逐调用点差异] 同名函数在多个调用点参数不同时，去重后只校验
  第一个调用点，其余"漏网"仍报全绿。正确做法：契约扫描器**逐调用点**校验（不去重），并把"前端
  传参 vs 函数签名 vs 必填参数反查"三方都查。
- [bool/tuple/dict/None 混合返回契约误判] 同类操作返回类型不一致：watcher.start 返回 bool、
  add_target 返回 tuple、stop 原返回 None、pcap.start_capture 返回 (bool,dict)。前端 `bizFail(null)`
  把成功停止判失败、GUI `isinstance(r,(tuple,list))` 把 bool 判失败。正确做法：每个调用点逐一核对
  后端真实返回类型；bool 用 bool(r)、tuple 用下标、None 要显式约定（最好让 stop 也返回 True）。
- [NaN→JSON null→int(None) TypeError] 前端 `Number("abc")` 得 NaN，JSON.stringify 变 null，
  后端 `int(task_id)` 直接 TypeError。正确做法：前端提交前用 `Number.isFinite(n) && n>0` 校验并
  拦截，后端对 id 类参数加 int() 转换 + try/except 友好错误（双入口防护）。
- [文档与代码决策不同步] 改一处决策后，Design/Techniques/FreqErr/README 里同义的旧句残留
  （如 Design §10 的"Canvas 启停不暴露给 Web API"在 §10 其它句已改后仍残留）。正确做法：改代码后
  对全部根目录文档 grep 同义关键词，把每处旧表述逐一更新（文档单套制 + 最新状态一致性）。

## 19. 第二轮检修：端口清零与实现加固（2026-08-16）

- [HTTP 方法级端口缺失] Design 文档声明 `DELETE/PUT /api/v1/tasks/{id}`，但 web_main 只有
  do_GET/do_POST，PUT/DELETE 请求 501/未处理——"口"写在文档上、"码"在 HTTP 方法层缺失。
  正确做法：API 面扩张时做"文档声明 × HTTP 方法 × 路由分支"三方矩阵核对；PUT/DELETE 与 POST
  一样过 CSRF 校验 + body 上限 + 字段白名单过滤（update_task 只透传可编辑键，未知键丢弃）。
- [进程"树"实为全系统列表] watcher._process_tree 返回全系统 tasklist，导致 _connections_for
  按全系统 PID 过滤 = 全网连接误归因为目标行为。正确做法：`wmic process get
  ProcessId,ParentProcessId /value` 建真实父子树（行配对解析失败要复位 pending 状态，防陈旧
  parent 错配）；tasklist 瞬时失败与"目标已退出"是两件事——用 None 语义区分；退出事件一次性
  去重（集合标记 + 重加同名目标时复位）。
- [内部状态字段与前端判定键重名] pcap `Capture.snapshot()` 的 `"error"` 字段与前端 bizFail 的
  `r.error` 判定同键，error 态快照会被误判业务失败（或改名后误判不失败）。正确做法：内部字段
  改名 `last_error`，前端 bizFail/bizErr 同时识别 error/last_error/state，避免"判定键"与"数据键"
  重名。
- [返回 None 的写操作导致假成功/假失败] remove_watch/prune/stop_all 返回 None，前端只能无条件
  报成功；stop_capture 无实例返回 None 被 bizFail(null) 判"停止失败"。正确做法：写操作一律返回
  可判定结果——bool（是否存在/是否移除）、int（清理/停止数量）、或幂等状态快照 dict。
- [自动落库缺审计] evolve mine_rules/adjust_weights 的 auto_apply=true 直接写 knowledge 而无
  audit，破坏"所有写库动作可审计"闭环。正确做法：任何 auto_apply/确认写库路径必须 db.audit，
  且同一次调用内把新写入的 title 实时加入去重集（防多分组生成相同标题重复写库）。
- [名实不符的"调整"函数] adjust_weights 只统计不调权，按钮名误导。正确做法：要么改名"统计"，
  要么真正实现（本轮：热点类别启用规则 risk_weight +0.05、auto_apply 门禁、候选列表回显、审计）。
- [ES6 简写属性导致契约扫描漏提取] `api("m","f",{before, after})` 的简写属性无冒号，按 `k:` 提取
  的扫描器漏检 → 假绿。正确做法：扫描器用状态机解析对象字面量（值上下文 vs 键上下文 + 简写属性
  在 `,`/`}` 前 flush），并逐调用点不去重。
- [重构移动代码块时误删关键行] 把 `auto_apply` 落库从循环内移到循环外时，new_string 漏写
  `rules.append(item)`，导致 mine_rules 恒返回空规则、落库死路——终检轮子 AGENT 抓出（对照旧
  backup 版本逐行比对发现）。正确做法：①重构"搬块"类编辑后立即读回全文与旧版 diff 核对每一行
  去向；②给关键闭环（规则挖掘→落库→去重）建独立回归测试（`_verify_evolve.py` 用临时库 seed 两个
  同类别观察，断言 preview 有候选、apply 恰好写 N 条、二次 apply 不重复）。

## 20. 第三轮检修：全量刁难与极端测试（2026-08-16）

- [测试脚本快照别名污染真实配置] `sw = config.get()["switches"]` 是活字典引用，测试先
  `set_switches(tracking=False)` 再"恢复"`set_switches(**sw)` 时，sw 里的 tracking 已是 False，
  恢复动作把 False 写回 config.json——用户的真实开关被测试写坏。正确做法：快照用 `dict()` 深拷贝；
  恢复后追加断言"恢复成功"（读回比对），确保测试自身可自证。
- [bool("false")==True 残留于多模块] evolve.mine_rules/adjust_weights 对 auto_apply 直接真值判断、
  privacy_guard.sandbox_preview/set_canvas_guard/_validate_action 用 bool() 或原样透传——HTTP 传字符串
  "false" 时被当 True：auto_apply 意外落库、Sandbox 意外开网、Canvas 意外启用。正确做法：每个收外部
  布尔参数的函数统一 `_strict_bool`（bool/0-1/白名单字符串，其余 ValueError）；测试用 "notabool" 断言
  业务拒绝。
- [HTTP 方法×集合路由矩阵缺失] DELETE/PUT `/api/v1/tasks`（集合）落入 `create_task(**body)` 分支，
  返回"任务名不能为空"这类误导错误（看起来像试图建任务）。正确做法：集合路由只允许 GET/POST，其余
  方法抛 `_MethodNotAllowed` 映射 405；已知子资源（events/runs/start/...）方法不匹配也 405，未知路由
  才 400。测试用"方法矩阵"逐格断言。
- [前端 run() 丢弃回调返回值致 bizFail 系统性失效（假成功总根因）] `run(id, fn, okMsg)` 只取
  `await fn()` 的结果，而大量按钮回调 `return "完成"` 硬编码字符串——真实 API 结果被丢弃，
  bizFail 永远看不到 {ok:false}/[false,msg]/null，破坏性操作（批量清理/恢复/标记入库）失败也绿字。
  正确做法：①回调必须 `return r`（或先 `if (bizFail(r)) throw` 再返回摘要）；②run() 把字符串返回值
  当作动态状态文案（保留"N 条"信息）；③run() 把 undefined 视为用户取消的中性退出（"已取消"），
  否则 confirm 取消会被 bizFail(undefined) 误报红字失败。
- [%.2f 格式化 dict 致页面功能死且异常被吞] decompile.analyze 的 `score` 是 {"high","med","suspicious"}
  dict，GUI 回调 `"%.2f" % r.get("score")` 抛 TypeError，被 _Invoker 静默吞掉，其后表格填充永不执行——
  反编译"概览/可疑调用"整页对任何有效文件恒空白。正确做法：消费跨模块结果前先确认字段类型
  （score 按 dict 三个计数分别展示），回调先判 error 再走成功路径。
- [send_command 投递数 0 被当成功] browser.send_command 返回已投递的扩展连接数（int），GUI/Web 把
  int 一律当成功——无扩展在线（0）也显示"已发送/已执行"。正确做法：int 语义显式处理，0 判失败并提示
  "无扩展连接在线"；带参数命令（activate 缺 tabId、observe_dom 缺 enabled）此前端到端不可用，补专用
  按钮 + 扩展侧参数守卫。
- [验证脚本断言与运行时配置耦合] _verify_ai.py 假设"AI 未配置"，config.json 配置真实 key 后测试触发
  真实外联，线程长时间运行，进程退出时 QThread 销毁崩溃（exit 0xC0000409）。正确做法：测试内打桩
  （`modules.ai.configured = lambda: False`）确定性走"未配置"分支，验证脚本与用户运行时配置解耦。
- [MV3 SW 空闲终止 + 心跳/超时同周期竞态] 扩展 service worker 空闲约 30s 即被杀，setInterval 在休眠期
  不运行、WebSocket 断连；后端 recv 超时 30s 与扩展心跳 30s 是两个独立计时器，阈值处毫秒级漂移就让
  中枢先断链→扩展 5s 后重连→周期抖动。正确做法：chrome.alarms（0.5min，旧版回落 1min）定期唤醒 SW
  重连；后端空闲超时放宽到明显大于心跳（75s），并单列 socket.timeout 为正常回收路径。
- [同一 DOM 事件双重转发] content.js（document_start 常驻）已转发 __rtDom，background.js 又在每次
  status=complete 时再注入一条同功能监听→每条 MutationObserver 上报被转发两次，DOM 事件统计翻倍。
  正确做法：转发只保留一处；注入类监听做幂等标记。
- [朴素括号计数误报] _check_js.py 去注释/字符串后仍把正则字面量里的括号计入（jsonBlock 的 lookbehind
  正则含 [ 与 ]）→ 假 UNBALANCED。正确做法：环境有 node 时一律 node --check（本机 2026-08-16 起
  node 24 可用），粗检仅作无 node 环境的参考。
- [超限请求体 413 早响应引发客户端 10053 假阳性] 服务端读 body 前先按 Content-Length 判断超限并立即
  413 关连接，客户端仍在发送时收到 RST（WinError 10053）。这是"早响应+关连接"的正常副作用，不是
  服务崩溃。正确做法：极端测试的乱型负载控制在 MAX_BODY 以内（单独用专测覆盖 413），并把 10053
  当作预期响应路径而非 crash。

## 21. 指纹扫描与格式逆向新增常见错误（2026-08-23）

- [沙箱/服务上下文环境变量陷阱] 沙箱或 SYSTEM 服务上下文里 `APPDATA`/`LOCALAPPDATA` 指向
  `C:\Windows\system32\config\systemprofile\...`，直接按环境变量扫用户目录会漏掉全部真实用户
  指纹；且 systemprofile 目录若先被扫描会占满 max_items 预算导致真实用户目录被截断。正确做法：
  `_user_scan_dirs` 枚举 `C:\Users\*` 真实 profile 并排除 system32\config 前缀；扫描遍历设
  目录数/文件数/时间三重预算护栏。
- [DPAPI magic 只匹配文件开头] base64 DPAPI blob 有两种形态：纯 blob（magic 在偏移 0）与
  "DPAPI\x01" ASCII 前缀变体（magic 在偏移 5，如 Qoder Local State 的 encrypted_key）。
  只查 `raw[:8] == magic` 会漏掉后者。正确做法：解码后前 40 字节内 `magic in raw` 搜索。
- [10 位数字字符串漏判时间戳] `installation_date2: "1786418606"` 是字符串形态 Unix 秒级
  时间戳，仅按 int 判断会归为普通数字串。正确做法：字符串分支同样做 10 位值域校验
  （946684800~4102444800）。
- [替换值生成不自洽] 给任意 hex 字段生成替换值时用 `uuid4().hex * 2` 会改变原长度（如 24 字符
  变 64 字符），软件按原长度校验即判损坏→重新制造指纹。正确做法：`secrets.token_hex(n//2)[:n]`
  保持原长，并加回归断言"生成的替换值必须再次通过同一格式校验"。
- [Python 函数签名默认值顺序] `def f(a=默认, b)` 直接 SyntaxError，批量新增函数时容易在
  `out` 这类必填参数后误加默认值参数。正确做法：写完立即 py_compile，不要攒批。
- [测试预期写错当代码错] `cache\id` 内容 `64343263-3763-452d-b130-30773a31362d` 本身就是合法
  UUID 文本（版本位 4/变体位 b），最初误判为"hex 编码"而期望 hex_uuid，把正确结果当 MISMATCH。
  正确做法：格式识别先人工核验真实内容语义，再定测试预期。

## 22. AI 指纹指导安全机制新增常见错误（2026-08-23）

- [LLM 无领域知识即指导指纹修改] 通用 LLM 不知道 Qoder machineid 必须是 UUID v4、不知道
  device_id_salt 是 hex32、不知道 encrypted_key 是 DPAPI blob。凭空生成的"替换值"无法保证
  通过软件格式校验。正确做法：先把 `analyze_fingerprint_format` + `generate_trusted_fingerprint`
  的确定性结果作为上下文注入 LLM 系统提示，让 LLM 基于事实生成指导。
- [指纹修改指导无安全门槛] 直接让 LLM 回答"怎么改指纹"可能帮助绕过付费/授权。正确做法：
  三层防线——①前置关键词黑名单拦截（付费/VIP/注册码等）②LLM 系统提示强制自检 + 【已检查】
  标记 ③返回后验证标记，缺失则追加警告。
- [LLM 自动执行写盘] 指纹修改涉及写盘操作，若 LLM 输出被工具自动执行可能破坏运行中进程文件。
  正确做法：硬行为边界"绝不自动执行"，所有步骤均为人工审查后手动执行；前置检查拒绝运行中 exe。
- [DPAPI blob 检测只查偏移 0] base64 DPAPI 有纯 blob（magic 在 0）和 "DPAPI\x01" ASCII 前缀
  （magic 在偏移 5）两种形态。只查 raw[:8] 漏后者。正确做法：前 40 字节内搜索 magic。
- [替换值长度不自洽] 任意 hex 字段用 uuid4().hex*2 生成替换值会改变原长度（24→64 字符），
  软件按原长度校验即判损坏。正确做法：secrets.token_hex(n//2)[:n] 保持原长。

## 23. Agent 工具权限分级新增常见错误（2026-08-23）

- [cmd 工具被 reviewer allow 后自动执行] 原三级权限下 cmd 工具 reviewer allow 即自动执行，
  用户无法干预。正确做法：简化为两级——只读自动放行，所有读写（cmd + high）一律请示用户。
- [Agent 工具无法调用指纹扫描] 原有 Agent 工具集缺少指纹扫描/逆向分析能力。正确做法：
  新增 8 个只读工具（scan_fingerprints / analyze_fingerprint_format 等）+ 1 个读写工具
  （modify_fingerprint），注册到 tools.TOOLS。
- [modify_fingerprint 未备份即写盘] 直接写盘无备份，出错无法回滚。正确做法：先复制到
  backups/quarantine/<ts>/ 再写盘，返回备份路径供回滚。
- [modify_fingerprint 未回读验证] 写盘后不验证，可能写入失败但报告成功。正确做法：写盘后
  回读文件内容，比对新值，返回 written_match 字段。
- [Agent 系统提示未区分工具权限] 原有 AGENT_SYS 未明确只读/读写区别。正确做法：系统提示
  明确分两类权限 + 硬行为边界（绝不自动执行读写、不指导绕过付费墙）。


## 25. 全量检修发现的潜伏缺陷（2026-08-24）

- [except 变量被闭包延迟引用 → NameError] 原 ui/gui.py _mod() 在 except Exception as e 块内
  定义 _fail 闭包并引用 e，返回时 except 块退出、解释器删除 e，之后调用 _fail() 直接抛
  NameError 而非返回优雅降级 dict。正确做法：在 except 块内先把错误格式化成字符串，
  闭包只捕获字符串。（pyflakes 静态扫描发现）
- [索引文件缺失被记 Err.log 造成启动误报] modules/embedding._load 对不存在的索引文件走
  record_err，首次运行必污染 Err.log，导致下次启动误报“检测到未修复错误”。正确做法：
  先 os.path.exists 静默返回 False，只有存在但损坏才算错误。
- [布尔解析四份拷贝且语义不一] config._parse_bool(非法返 None) / evolve._strict_bool(raise)
  / privacy_guard._strict_bool(raise) / tracking._to_bool(raise) 四份近似实现，正是历史
  string-"false" 蠕虫的温床。正确做法：全库统一 core/coerce.py 三件套
  （parse_bool / as_bool / strict_bool），其余一律委托。
- [2200 行单文件 screener / 3000 行单文件 gui] 多域职责混杂导致改动风险高、回归无法定位。
  正确做法：按职责拆包 + 入口平面再导出保持零调用方改动 + 拆分后跑全量回归。


## 26. 全量检修第二轮：安全守卫与前端致命缺陷（2026-08-25）

- [CSS 注释内嵌星斜杠 = 整表报废] 注释文本写 "views_*/boot" 时，`*/` 提前终止注释，
  其后 `boot 契约）==== */ :root {...}` 被解析器按"非法规则+块"整体吞掉——:root
  全部自定义属性未注册，所有 var() 静默失效，页面半白半黑且无任何报错。
  正确做法：注释内严禁 `*/` 序列；用 CSSOM（document.styleSheets[0].cssRules）
  验证规则数量，而不是只看文件字节。
- [builder 回调引用未初始化外层 const = TDZ] viewTemplate 的 builder 在 const body
  初始化完成前同步执行，builder 内引用外层 body 即 ReferenceError，且 async boot
  里表现为 unhandledrejection 而非同步崩溃，极易漏诊。正确做法：builder 一律从
  入参解构 `{ body, output, log }`；诊断用 window.addEventListener("unhandledrejection")。
- [tshark -X lua_script = 白名单内的任意代码执行] run_command 只拦 -w/-F/-G 时，
  `-X lua_script:file` 可借 tshark 内置 Lua 引擎执行任意代码。正确做法：对可执行
  白名单命令做"显式参数安全集"校验（长选项一律拒绝），而不是只拉黑已知危险项。
- [ipconfig 多开关夹带] 只校验 argv[1] 时 `/all /release` 可夹带破坏性动词。
  正确做法：遍历全部开关参数逐一校验，或模板化固定 argv。
- [manifest 后置落盘违反恢复不变量] 清理循环全部结束才写 manifest.json，
  中途崩溃=已隔离文件成孤儿、无法一键恢复。正确做法：先写空 manifest，
  每处理完一项原子重写（tmp+replace+fsync）。
- [隔离物撞保留名] 被隔离文件恰好叫 manifest.json 时会被最终清单截断覆盖。
  正确做法：隔离目标对保留名强制改名，并在 manifest 记录 renamed_from。
- [注册表备份宽 except OSError 把"部分不可读"当"已不存在"] 深层子键无权限时
  整树备份作废→返回"已不存在"→虚报清理成功且无备份。正确做法：区分
  FileNotFoundError（真不存在）与权限类 OSError（中止并拒绝删除）；枚举循环
  结束的 winerror 259（ERROR_NO_MORE_ITEMS）必须与真错误区分。
- [Windows SO_REUSEADDR 允许双绑] 冲突检测用 bind 失败判断时，SO_REUSEADDR
  在 Windows 上允许二次绑定同端口，检测永远不触发。正确做法：单实例工具用
  SO_EXCLUSIVEADDRUSE。
- [history 单槽覆盖毁掉关键信号] 漂移监测 history 每路径只存最后值时，
  "A→B→删除→A 复活"被误判为 regenerated 而非 recreated_same_value。
  正确做法：每路径累积历史态集合（FIFO 上限），判定同时校验 sha+size。
- [TextMetrics 克隆丢 IDL getter] Object.create(proto) 的裸对象读取
  actualBoundingBoxAscent 等会 Illegal invocation。正确做法：逐字段从真实
  对象取值包普通对象返回。
- [AudioBuffer.getChannelData 每次加噪会累积漂移] 活缓冲被反复读取时噪声
  叠加破坏音频。正确做法：WeakSet 去重，仅首读一次性注入确定性微扰。
