function vAi() {
  const body = viewTemplate("v_ai", "大模型集成", "M8 · AI", "spark", "analysis", ({ output }) => {
    // ① 状态
    const statusBtn = btn("检查 AI 是否已配置", async () => {
      await run("ai", async () => {
        const c = await api("ai", "configured");
        output.innerHTML = ""; output.appendChild(jsonBlock({ configured: c }));
        return c ? "已配置" : "未配置（请在设置或 config.json 配 base_url/api_key/model）";
      });
    });

    // ② 问答
    const q = textarea("向大模型提问（自动叠加只读顾问边界）", "", 3);
    const askBtn = btn("提问", async () => {
      await run("ai", async () => {
        const r = await api("ai", "answer",
          { question: q.value, context: "ReTrace 漏洞分析助手" });
        if (bizFail(r)) throw new Error("提问失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    }, false, true);

    // ③ 单项能力
    const inText = textarea("在此粘贴 / 输入文本，按不同按钮执行不同动作", "", 5);
    const btnAnalyze = btn("AI 风险分析", async () => {
      await run("ai", async () => {
        const r = await api("ai", "analyze", { finding: inText.value });
        if (bizFail(r)) throw new Error("分析失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const btnSummary = btn("AI 摘要", async () => {
      await run("ai", async () => {
        const r = await api("ai", "summarize", { observation: inText.value });
        if (bizFail(r)) throw new Error("摘要失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const btnRules = btn("AI 规则提炼", async () => {
      const list = inText.value.split(/\r?\n/).filter(s => s.trim());
      await run("ai", async () => {
        const r = await api("ai", "extract_rules", { observations: list });
        if (bizFail(r)) throw new Error("提炼失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const btnChat = btn("直连对话（chat）", async () => {
      const list = inText.value.split(/\n\n+/).filter(Boolean);
      const messages = list.length ? list.map((t, i) =>
        ({ role: i % 2 === 0 ? "user" : "assistant", content: t }))
        : [{ role: "user", content: inText.value }];
      await run("ai", async () => {
        const r = await api("ai", "chat", { messages: messages });
        if (bizFail(r)) throw new Error("对话失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    body.appendChild(card("① 状态", [toolbar([statusBtn])]));
    body.appendChild(card("② 上下文问答（ask）",
      [q, toolbar([askBtn], { primary: true })]));
    body.appendChild(card("③ 单项能力", [
      inText,
      toolbar([btnAnalyze, btnSummary, btnRules, btnChat]),
      hint("analyze=finding 文本；summarize=observation 文本；extract_rules=每行一条观察;"
         + " chat=传入完整 messages 列表（按 \\n\\n 切片自动分配 user/assistant）。"),
    ]));
    body.appendChild(card("④ 结果", [output]));
  });
}

/* ============================================================
   任务追踪（vTracking，全套跟踪任务操作）
   ============================================================ */
function vTracking() {
  const body = viewTemplate("v_tracking", "追踪任务", "DAEMON · TASKS", "clock", "flow", ({ output }) => {
    // ① 全局：刷新 + 验证审计链
    const refreshBtn = btn("刷新任务", async () => {
      await run("tracking", async () => {
        const rows = await api("tracking", "list_tasks");
        output.innerHTML = ""; output.appendChild(table(rows || [], "当前任务"));
        return (rows || []).length + " 个";
      }, "已刷新");
    });
    const verifyBtn = btn("验证审计链", async () => {
      await run("tracking", async () => {
        const r = await api("tracking", "audit_verify");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        if (!r || r.ok !== true) throw new Error("审计链验证未通过（详见输出）");
        return "链完整（" + (r.checked || 0) + " 条）";
      }, "验证完成");
    });
    const auditBtn = btn("查看全局审计", async () => {
      await run("tracking", async () => {
        const rows = await api("tracking", "audit_entries", { limit: 100 });
        output.innerHTML = ""; output.appendChild(table(rows || [], "审计日志"));
        return (rows || []).length + " 条";
      }, "已加载");
    });
    const capsBtn = btn("查看采集能力", async () => {
      await run("tracking", async () => {
        const r = await api("tracking", "capabilities", {});
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    // ② 创建任务
    const tName = input("任务名（必填）"); const tExe = input("可执行文件路径");
    const tProc = input("进程名"); const tPaths = input("观察目录（分号分隔）");
    const tInterval = input("采样间隔（秒）", "", "5");
    const tAi = checkbox("启用 AI 摘要", false);
    const createBtn = btn("创建并启动", async () => {
      if (!tName.value) { toast("任务名必填", "warn"); return; }
      const paths = (tPaths.value || "").split(";").map(s => s.trim()).filter(Boolean);
      await run("tracking", async () => {
        const r = await api("tracking", "create_task", {
          name: tName.value, exe_path: tExe.value || "", process_name: tProc.value || "",
          watch_paths: paths, interval_sec: Number(tInterval.value) || 5,
          ai_enabled: tAi.input.checked, auto_start: true,
        });
        if (!r || !r.id) {
          throw new Error("创建失败：" + ((r && (r.error || r)) || "未知错误"));
        }
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已创建 #" + r.id;
      }, "已创建");
    }, false, true);

    // ③ 选中任务后的操作
    const tId = input("任务 ID");
    // NaN/负数/小数统一拦截：Number("abc")=NaN 会经 JSON 变 null，后端 int(None) 才报错，
    // 在这里先把非法输入挡在门外，返回 0 由各按钮 toast 提示。
    const readTaskId = () => {
      const n = Number(tId.value);
      if (!tId.value.trim() || !Number.isFinite(n) || n <= 0) {
        toast("请输入有效的任务 ID（正整数）", "warn"); return 0;
      }
      return Math.trunc(n);
    };
    const startBtn = btn("启动", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const r = await api("tracking", "start_task", { task_id: tid });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已启动";
      });
    });
    const pauseBtn = btn("暂停", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const r = await api("tracking", "pause_task", { task_id: tid });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已暂停";
      });
    });
    const editBtn = btn("编辑", async () => {
      const tid = readTaskId(); if (!tid) return;
      const newName = window.prompt("新任务名", "");
      if (!newName) return;
      await run("tracking", async () => {
        const r = await api("tracking", "update_task",
          { task_id: tid, name: newName });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已更新";
      });
    });
    const deleteBtn = btn("删除", async () => {
      const tid = readTaskId(); if (!tid) return;
      if (!confirm("确认删除任务 #" + tid + "？其事件与运行历史将一并删除。")) return;
      await run("tracking", async () => {
        const r = await api("tracking", "delete_task", { task_id: tid });
        if (bizFail(r)) throw new Error("删除失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已删除";
      });
    });

    // ④ 查看事件 / 运行 / AI 摘要
    const evLimit = input("事件条数", "", "300");
    const evBtn = btn("查看事件", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const rows = await api("tracking", "task_events",
          { task_id: tid, limit: Number(evLimit.value) || 300 });
        output.innerHTML = ""; output.appendChild(table(rows || [], "事件"));
        return (rows || []).length + " 条";
      }, "已加载");
    });
    const runsBtn = btn("查看运行历史", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const rows = await api("tracking", "task_runs", { task_id: tid });
        output.innerHTML = ""; output.appendChild(table(rows || [], "运行历史"));
        return (rows || []).length + " 条";
      }, "已加载");
    });
    const aiBtn = btn("AI 风险摘要", async () => {
      const tid = readTaskId(); if (!tid) return;
      await run("tracking", async () => {
        const r = await api("tracking", "analyze_task", { task_id: tid });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        if (!r || !r.text) throw new Error("AI 摘要失败：" + (r && r.error ? r.error : "无返回文本"));
        return "AI 完成";
      }, "AI 完成");
    });

    body.appendChild(card("① 全局", [
      toolbar([refreshBtn, verifyBtn, auditBtn, capsBtn], { primary: true }),
    ]));
    body.appendChild(card("② 创建任务", [
      formRow([["任务名", tName], ["可执行文件", tExe], ["进程名", tProc]]),
      formRow([["观察目录", tPaths], ["间隔(秒)", tInterval], ["AI 摘要", tAi.input]]),
      toolbar([createBtn]),
    ]));
    body.appendChild(card("③ 选中任务后操作（按 ID）", [
      formRow([["任务 ID", tId]]),
      toolbar([startBtn, pauseBtn, editBtn, deleteBtn]),
    ]));
    body.appendChild(card("④ 详情（事件/运行/AI）", [
      formRow([["事件条数", evLimit]]),
      toolbar([evBtn, runsBtn, aiBtn]),
    ]));
    body.appendChild(card("⑤ 结果", [output]));
  });
}

/* ============================================================
   隐私保护（vPrivacy，全套门禁操作）
   ============================================================ */
function vPrivacy() {
  const body = viewTemplate("v_privacy", "隐私保护", "PRIVACY GUARD", "shield", "system", ({ output }) => {
    const reasonInput = input("明确原因（≥12 字：目的、对象、必要性）", "wide");
    const taskIdInput = input("任务 ID（归属）");
    const subkey = input("HKCU 子树（Software\\厂商\\产品）");
    const valueName = input("值名（可空）");
    const newVal = input("新 REG_SZ 值（设置用）");
    const publisher = input("发布者（登记用）");
    const owner = input("所有权说明（≥12 字）", "wide");
    const exe = input("EXE 路径（隔离用）");
    const net = checkbox("允许联网", false);
    const clip = checkbox("允许剪贴板", false);
    const site = input("Canvas 站点（例 https://example.com）");

    // ① 能力
    const capsBtn = btn("查看能力", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "capabilities");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const rulesBtn = btn("查看保护规则", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "protected_rules");
        output.innerHTML = ""; output.appendChild(table(r || [], "保护规则"));
        return (r || []).length + " 条";
      });
    });
    // 任务 ID 统一校验：拦截 NaN/负数/小数，避免 JSON null 传后端 int(None) TypeError
    const readPrivacyId = () => {
      const n = Number(taskIdInput.value);
      if (!taskIdInput.value.trim() || !Number.isFinite(n) || n <= 0) {
        toast("请输入有效的任务 ID（正整数）", "warn"); return 0;
      }
      return Math.trunc(n);
    };
    const taskReportBtn = btn("查看任务报告", async () => {
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const r = await api("privacy_guard", "task_report", { task_id: tid });
        if (bizFail(r)) throw new Error("报告失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const registryScopesBtn = btn("查看已登记的 HKCU 范围", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "registry_scopes", {});
        output.innerHTML = ""; output.appendChild(table(r || [], "已登记范围"));
        return (r || []).length + " 项";
      });
    });

    // ② 隔离
    const previewBtn = btn("预览 WSB（只读映射）", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "sandbox_preview",
          { exe_path: exe.value, network: net.input.checked, clipboard: clip.input.checked, memory_mb: 4096 });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const planLaunchBtn = btn("审查并启动 Sandbox", async () => {
      if (!exe.value) { toast("请填写 EXE 路径", "warn"); return; }
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action", {
          action: "launch_sandbox",
          args: { exe_path: exe.value, network: net.input.checked, clipboard: clip.input.checked, memory_mb: 4096 },
          reason
        });
        if (!plan || !plan.token) throw new Error("计划创建失败：" + bizErr(plan));
        if (!confirm("即将执行：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action", {
          token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog"
        });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action", {
          approval_token: cap.approval_token, reason
        });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "完成");
    });

    // ③ 注册表登记 / 撤销
    const registerBtn = btn("登记 HKCU 子树", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value) { toast("请填写子树", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const r = await api("privacy_guard", "register_registry_scope", {
          task_id: tid, root: "HKCU", subkey: subkey.value,
          publisher: publisher.value || "", ownership_note: owner.value, reason,
          confirmation: "我已审查并批准"
        });
        if (bizFail(r)) throw new Error("登记失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已登记");
    });
    const removeScopeBtn = btn("撤销 HKCU 子树登记", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value) { toast("请填写子树", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const r = await api("privacy_guard", "remove_registry_scope", {
          task_id: tid, subkey: subkey.value, reason,
          confirmation: "我已审查并批准"
        });
        if (bizFail(r)) throw new Error("撤销失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已撤销");
    });
    const setBtn = btn("审查·设置值", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value || !valueName.value) { toast("必填 子树/值名", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action", {
          action: "registry_set_string",
          args: { task_id: tid, root: "HKCU", subkey: subkey.value,
                 value_name: valueName.value, new_value: newVal.value || "" },
          reason
        });
        if (!plan || !plan.token) throw new Error("计划失败：" + bizErr(plan));
        if (!confirm("设置 HKCU 注册表值：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action", {
          token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog"
        });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action", {
          approval_token: cap.approval_token, reason
        });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已设置");
    });
    const delBtn = btn("审查·删除值", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!subkey.value || !valueName.value) { toast("必填 子树/值名", "warn"); return; }
      const tid = readPrivacyId(); if (!tid) return;
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action", {
          action: "registry_delete_value",
          args: { task_id: tid, root: "HKCU", subkey: subkey.value,
                 value_name: valueName.value },
          reason
        });
        if (!plan || !plan.token) throw new Error("计划失败：" + bizErr(plan));
        if (!confirm("删除 HKCU 注册表值：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action", {
          token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog"
        });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action", {
          approval_token: cap.approval_token, reason
        });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已删除");
    });

    // ④ Canvas / WLAN
    const enableCanvasBtn = btn("启用 Canvas 扰动", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!site.value) { toast("请填写站点", "warn"); return; }
      await run("privacy", async () => {
        const r = await api("privacy_guard", "set_canvas_guard",
          { site: site.value, enabled: true, reason });
        if (bizFail(r)) throw new Error("启用失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const disableCanvasBtn = btn("停用 Canvas 扰动", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      if (!site.value) { toast("请填写站点", "warn"); return; }
      await run("privacy", async () => {
        const r = await api("privacy_guard", "set_canvas_guard",
          { site: site.value, enabled: false, reason });
        if (bizFail(r)) throw new Error("停用失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const macBtn = btn("WLAN 随机硬件地址能力", async () => {
      await run("privacy", async () => {
        const r = await api("privacy_guard", "mac_randomization_status", {});
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const wifiBtn = btn("审查·打开 Windows WLAN 设置", async () => {
      const reason = reasonInput.value.trim();
      if (reason.length < 12) { toast("请写明至少 12 字原因", "warn"); return; }
      await run("privacy", async () => {
        const plan = await api("privacy_guard", "plan_system_action",
          { action: "open_wifi_privacy_settings", args: {}, reason });
        if (!plan || !plan.token) throw new Error("计划失败：" + bizErr(plan));
        if (!confirm("打开 Windows WLAN 隐私设置：\n" + JSON.stringify(plan, null, 2))) return;
        const cap = await api("privacy_guard", "approve_system_action",
          { token: plan.token, confirmation: "我已审查并批准", reason, approval_context: "web_dialog" });
        if (!cap || !cap.approval_token) throw new Error("批准失败：" + (cap && cap.error ? cap.error : "无批准能力"));
        const r = await api("privacy_guard", "execute_system_action",
          { approval_token: cap.approval_token, reason });
        if (bizFail(r)) throw new Error("执行失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    body.appendChild(card("全局原因（必填 ≥12 字，所有系统操作都看这里）",
      [formRow([["原因", reasonInput]])]));
    body.appendChild(card("① 能力 / 报告 / 范围", [
      formRow([["任务 ID", taskIdInput]]),
      toolbar([capsBtn, rulesBtn, taskReportBtn, registryScopesBtn], { primary: true }),
    ]));
    body.appendChild(card("② Sandbox 隔离", [
      formRow([["EXE", exe]]),
      toolbar([net, clip, "spacer", previewBtn, planLaunchBtn], { primary: true }),
    ]));
    body.appendChild(card("③ HKCU 注册表（先登记再修改）", [
      formRow([["子树", subkey], ["值名", valueName], ["新值", newVal]]),
      formRow([["发布者", publisher], ["所有权说明", owner]]),
      toolbar([registerBtn, removeScopeBtn, "spacer", setBtn, delBtn]),
      hint("HKLM 与系统身份范围确定性拒绝；HKCU 子树必须先登记并绑定 task + EXE。"),
    ]));
    body.appendChild(card("④ Canvas / WLAN", [
      formRow([["站点", site]]),
      toolbar([enableCanvasBtn, disableCanvasBtn, "spacer", macBtn, wifiBtn]),
    ]));
    body.appendChild(card("⑤ 结果", [output]));
  });
}

/* ============================================================
   M9 漏洞主流程
   ============================================================ */
