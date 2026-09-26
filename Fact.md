# Fact.md — 用户偏好约束与事实记录

> 环境事实与用户约束的唯一事实源。原文件在历史迁移中遗失，2026-09-14 检修轮
> 依据 Design.md 决策记录与 FreqErr.md 历史重建；后续新事实登记于此。

## 环境事实
- 本机 Windows，项目路径 `C:\Users\david\Documents\all_projects\监控`（2026-09 迁移，
  旧路径 `C:\Users\Amily\Desktop\最近科创\监控` 已失效）。
- Python 3.12/3.13/3.14 实测可用；日常 PATH 为 miniforge 3.14。
- Wireshark 未安装：M1 抓包在本机自动降级为仅离线解析。
- Node 24 可用：Web/扩展 JS 改动后必须 `node --check`（FreqErr §6）。
- git 仓库存在（AGPL-3.0）；config.json / retrace.db / Err.log / tests/ / backups/
  均不入库（含真实 key 的测试数据历史上从未进过提交）。

## 用户约束（硬规则）
- 轻量化优先：非必要不引入第三方大依赖；首选标准库。
- 文件安全红线：禁止用命令行（bash/cmd/powershell）增删改复制回滚项目文件；
  大规模或不可逆操作先停下确认；重大失误立即停手、立即报告。
- 隐私分级：config.json 等含密钥文件绝不入 git、绝不回显明文；对话输出不粘贴密钥。
- 注册表一律只读不写（对 Agent 而言）；系统变更批准权永不授予 Agent。
- 文档单套制：Design.md 记"当前最新状态"，本轮事实进 FreqErr.md / Fact.md。

## 文档纪律（现行实际）
- 根目录文档：README / Design / Techniques / Fact / Future / FreqErr + Err.log。
- 早期 §7 的 todo.md / done.md / dev_log/ / updates/ 流程已退役：各轮记录统一
  落 Design 末节 + FreqErr 追加节 + Future 登记；备份在 backups/。
