# Future.md — 未来需求记录

> 本文件登记项目未来可能实现的需求、暂缓实现的想法与候选方案。
> 来源：
> - 由全局 AI Agent（`modules/ai.py`）在用户提出新方向时自动追加。
> - 由用户在对话中明确登记。
> - 历史归档：2026-08-15 创造力评测的优秀建议清单（来自 `todo (2).md` 的合并内容）。

---

## 来源：2026-08-15 创造力评测（10 项目 × 5 模型 × 10 条建议，DeepSeek-V4-Flash 千分制逐条裁判）

> 仅收录裁判判定【优秀】且无违规的建议；标注来源模型与当前处理状态。

### 1. Reviewer 模型对反编译危险 API 进行静态审计
- **来源模型**：glm-5.2
- **裁判理由**：在反编译模块中引入 Reviewer 模型对危险 API 做静态审计，契合 LLM 审核链与风险分级，增强本地分析安全性，创新且可落地。
- **当前状态**：✅ **已于 2026-08-15 实现**
  - 详见 `Design.md` §13 反编译危险 API 的 LLM 语义审计。
  - 实现入口：`modules/decompile.py::ai_audit(path)`，GUI/Web 均已接入。
  - 仍受 `SAFETY_SYS` 只读顾问边界约束，AI 未配置时降级返回静态评分。

### 2. 证据图谱聚类自动生成可复用狩猎剧本
- **来源模型**：MiniMax-M3
- **裁判理由**：契合证据归因模型与经验库沉淀闭环，创新且可落地。
- **当前状态**：🟡 **暂缓（用户确认）**
  - 暂缓原因（来自 `Design.md` §13 与 `updates/done_20260815_ai_audit.md`）：
    "证据图谱/聚类/狩猎剧本" 三者数据边界未定义，本轮不实现，避免过度工程。
  - 后续推进前置条件（三选一即重新评估）：
    1. 证据图谱（events 图节点/边的稳定 schema）定义并落地。
    2. 聚类算法与阈值确定（特征空间 + 命中统计）。
    3. 狩猎剧本（hunt script）DSL/模板格式定义。
  - 一旦前置条件齐备，由全局 AI Agent 或用户在对话中重新激活。

---

## 来源：2026-09-14/15 十三路深度检修轮（已核实、本轮未修，按优先级登记）

> 以下条目均经源码核实成立，因改动面/风险超出本轮预算或需产品决策而登记待办。
> 状态一律 pending；处理时逐条到源码复核（行号可能随本轮修复漂移）。

### 1. browser 中枢多客户端路由（P2，需设计）
双浏览器并发时 tabId 跨浏览器撞号、_broadcast 无差别投递（modules/browser.py:271-279,
335-347）。需连接分配 client_id + 按 client 路由，改动面大。

### 2. 扩展隐私面收尾（P2）
- MAIN world 全局安装钩子可被页面预埋骗 seed（background.js:39-46）：合并为单次
  executeScript，seed 走参数不落 window 全局。
- OffscreenCanvas 2D 旁路未 hook（canvas_guard.js:22-24）；Worker 内不可 hook，
  至少 UI/popup 如实声明覆盖面。
- snapshot 抓取 input value 含 password 明文（background.js:221-223）：排除或
  value:"<hidden>"。

### 3. clear_site_traces 中枢链路（P2，二选一）
browser.py:434 白名单不含该命令而扩展有完整分支（死代码）。要么白名单补项并在
GUI/Web 加调用方，要么删扩展分支保持两端一致。

### 4. Web API 契约收尾（P3）
- db/config 内置分支业务失败以 {"error":…} 塞进 ok:true 封套（web_main.py:207 等），
  外部客户端按 ok 判定会误判成功；建议统一改 raise ValueError 走 400。
- limit 负数无钳制（:191,197,383）→ SQLite 负 LIMIT 全表拉取。
- 静态资源无 ETag/Last-Modified 且 no-store（:258）；favicon.svg MIME 缺失
  （:313-316，Firefox 不渲染）。

### 5. hunt 采集生命周期完备化（P2，本轮已部分修复）
finish_observation 已补 stop_capture("hunt") + watcher 移除；仍缺：collect_evidence
中途取消、regscan 观察键的同步移除、start_hunt 的 options 键无调用方（契约只存在
于实现）。

### 6. GUI 退出路径（P2，体验）
requestInterruption 对通用 worker 无效 + 每线程 wait(65000)：长任务期间实际退不出。
建议 wait 降到 2-5s + "正在收尾"模态 + 纯读任务强制退出兜底（gui.py:134-137）。

### 7. config.save 失败反馈断层（P2）
save() 静默吞 OSError，GUI 仍提示"已保存"（core/config.py:114-120 +
ui/pages/settings.py:104-108）。建议 save() 返回 bool 并透传到双端 UI。

### 8. sandbox_test_plan 产物自洽（P2）
占位 HostFolder 导致 .wsb 不可用、只读映射无法"带出"结果（privacy_guard.py:263-316）。
需复用 staging 逻辑生成真实目录 + 修正清单步骤。

### 9. 大样本反编译性能（P3）
common.py 逐字节双遍扫描 256MB 上限文件分钟级阻塞；字符串提取建议 mmap+正则；
UTF-16LE 宽字符串漏检需产品确认补扫。

### 10. 移除 wmic 依赖（P3）
watcher._parent_map 依赖 Win11 24H2 已移除的 wmic（watcher.py:200-232），建议补
PowerShell CIM 替代路径。

### 11. screener GUI 未暴露的能力（线索）
identity_hunt / investigation_case 全套能力只接入 Agent 工具，GUI 筛查页无入口、
包入口未再导出——确认是"Agent 独占"还是补 GUI 入口。

### 12. 已知取舍（留档，不算缺陷）
- 扩展 token 首帧 hello 协议维持查询串握手（FreqErr §28 决议）。
- seed 粒度 origin 而非 eTLD+1（需产品决策是否引 PSL）。
- GUI 审批对话框无超时（审批必须等人）。
- 冒烟 GUI 退出收尾已补（_gui_smoke.py）；真机退出路径见条目 6。

---

## 来源：2026-09-19 深度检修第二轮（已核实、本轮未修，按优先级登记）

### 1. redact 出口级全量改写的可用性代价（P2，需产品决策）
GUID/32-hex 形状规则作用于整个出参：含 GUID 的**路径**（file_hits、
identity_findings[].path）也被打码，模型侧拿不到真实路径喂给 read_file /
json_edit_field / derive_probe。隐私优先是本轮定案；若要完整实验链，候选方案 =
字段级脱敏（只脱 value/data 类字段）或带审计的人工放行通道。

### 2. experiment_backup / modify_fingerprint 明文快照 config.json（P3）
二者仍会把含 api_key 的 config.json 原文复制进 backups/experiments/（已 gitignore）。
是否对敏感文件快照做脱敏或拒绝，待用户决策。

### 3. monitor_identity_access 私有 Watcher 实例（P3）
identity_hunt.py:501 起 `Watcher({})` 独立实例：结果不进 UI 时间线、与全局采集
构成双份轮询。考虑复用全局 watcher 或在 status 中暴露私有实例。

### 4. 宽松"OSError=break"枚举位残留（P3，成套机械修）
本轮只统一了 identity_hunt 与 cleanup 的 winerror==259 甄别。同类还有：
regscan.py:150/207/305/399、activity.py:669/691、fsreg.py:361/385、
deep_scan.py:172/230——权限抖动会被当"枚举结束"，部分结果冒充全量。建议一次
成套修（helper 化 + 截断标记）。
（2026-09-19 加强项已机械化：`_verify_api_contract.py` [C2] 普查会拦住**新增**
未甄别枚举位；上述文件现在该脚本 _ENUM_EXEMPT 豁免清单挂账，修好一个删一个。）

### 5. 文档勘误留档（信息）
§22/§30 记载"+23 新回归"，tests/test_activity_tracking_fixes.py 实为 22 例；
§30 的"redact 包出口"修复对 GUID 实际无效（FreqErr §31 已收录并本轮修复）。
历史记录不回改，以此为准。

---

## 一般登记规则
- 新增条目时，注明"来源 / 提出日期 / 优先度 / 状态（pending / in_progress / blocked / done / shelved）"。
- 实现完成的条目转入 `done.md` 与 `dev_log/<日期>.md`，本文件保留条目并更新状态为 `done`，附跳转链接。
- 用户在对话中提出的非紧急改进想法，若不准备立刻动手，也登记于此。
