function vHunt() {
  const body = viewTemplate("v_hunt", "漏洞主流程", "M9 · HUNT", "target", "flow", ({ output }) => {
    const aname = input("目标名");
    const apath = input("路径");
    const agentsSel = el("select");
    const refill = async () => {
      // 用独立状态 id，避免与外层按钮的 run("hunt") 共用状态条互相覆盖
      await run("hunt_refill", async () => {
        const rows = await api("hunt", "list_agents");
        agentsSel.innerHTML = "";
        (rows || []).forEach(a => {
          const o = el("option", null, (a.name || "?") + " #" + a.id);
          o.value = a.id; agentsSel.appendChild(o);
        });
        return (rows || []).length + " 个";
      });
    };
    const regBtn = btn("登记目标", async () => {
      if (!aname.value) { toast("请填写目标名", "warn"); return; }
      await run("hunt", async () => {
        const r = await api("hunt", "create_agent",
          { name: aname.value, path: apath.value, kind: "app" });
        if (bizFail(r)) throw new Error("登记失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        refill();
        return "已登记";
      });
    }, false, true);
    onEnter(aname, regBtn); onEnter(apath, regBtn);
    const startBtn = btn("开始观察", async () => {
      if (!agentsSel.value) { toast("请先登记并选择目标", "warn"); return; }
      await run("hunt", async () => {
        const r = await api("hunt", "start_hunt",
          { agent_id: Number(agentsSel.value), title: "Web 集中观察" });
        if (bizFail(r)) throw new Error("开始观察失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已启动";
      });
    });
    const recentBtn = btn("最近观察", async () => {
      await run("hunt", async () => {
        const rows = await api("hunt", "recent_hunts", { limit: 30 });
        output.innerHTML = ""; output.appendChild(table(rows || [], "最近观察"));
        return (rows || []).length + " 条";
      }, "已加载");
    });

    // ③ 观察收尾：收集证据 / AI 分析 / 标记完成 / 详情（M9 观察-标记-沉淀闭环）
    const obsId = input("观察 ID（最近观察列表中的 id）");
    const readObsId = () => {
      const n = Number(obsId.value);
      if (!obsId.value.trim() || !Number.isFinite(n) || n <= 0) {
        toast("请输入有效的观察 ID（正整数）", "warn"); return 0;
      }
      return Math.trunc(n);
    };
    const collectBtn = btn("收集证据", async () => {
      const id = readObsId(); if (!id) return;
      await run("hunt", async () => {
        const r = await api("hunt", "collect_evidence", { obs_id: id });
        if (bizFail(r)) throw new Error("收集失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已收集 " + (r && r.evidence_blocks ? r.evidence_blocks + " 个证据块" : "");
      }, "已收集");
    });
    const aiBtn = btn("AI 分析观察", async () => {
      const id = readObsId(); if (!id) return;
      await run("hunt", async () => {
        const r = await api("hunt", "analyze_with_ai", { obs_id: id });
        if (bizFail(r)) throw new Error("AI 分析失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "AI 完成";
      }, "AI 完成");
    });
    const finishBtn = btn("标记完成", async () => {
      const id = readObsId(); if (!id) return;
      const risk = window.prompt("风险（高/中/低/无）", "低");
      if (!risk) return;
      const category = window.prompt("类别", "其他") || "其他";
      const mark = window.prompt("标记（可空）") || "";
      const conclusion = window.prompt("结论（可空）") || "";
      await run("hunt", async () => {
        const r = await api("hunt", "finish_observation",
          { obs_id: id, risk, category, mark, conclusion });
        if (bizFail(r)) throw new Error("标记失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已标记入库并回流经验";
      }, "已标记");
    });
    const detailBtn = btn("查看详情", async () => {
      const id = readObsId(); if (!id) return;
      await run("hunt", async () => {
        const r = await api("hunt", "get_hunt", { obs_id: id });
        if (r === null || r === undefined) throw new Error("观察 #" + id + " 不存在");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });

    body.appendChild(card("① 登记目标", [
      formRow([["目标名", aname], ["路径", apath]]),
      toolbar([regBtn], { primary: true }),
    ]));
    body.appendChild(card("② 选择目标 + 开始", [
      formRow([["目标", agentsSel]]),
      toolbar([startBtn, recentBtn], { primary: true }),
    ]));
    body.appendChild(card("③ 观察收尾（收集 → AI 分析 → 标记入库）", [
      formRow([["观察 ID", obsId]]),
      toolbar([collectBtn, aiBtn, finishBtn, detailBtn]),
      hint("标记完成会写入 observations 并回流 knowledge/embedding 经验库（观察-标记-沉淀闭环）。"),
    ]));
    body.appendChild(card("④ 结果", [output]));
    refill();
  });
}

/* ============================================================
   M5 自我进化（evolve）
   ============================================================ */
function vEvolve() {
  const body = viewTemplate("v_evolve", "自我进化", "M5 · EVOLVE", "broom", "analysis", ({ output }) => {
    const mineBtn = btn("挖掘候选规则", async () => {
      await run("evolve", async () => {
        const r = await api("evolve", "mine_rules");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      }, "已挖掘");
    });
    const adjustBtn = btn("调整观察权重", async () => {
      await run("evolve", async () => {
        const r = await api("evolve", "adjust_weights", { auto_apply: false });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成（候选调整，未落库）";
      });
    });
    const adjustApplyBtn = btn("调整并确认应用", async () => {
      if (!confirm("确认把热点类别规则的 risk_weight 上调 0.05 并落库？")) return;
      await run("evolve", async () => {
        const r = await api("evolve", "adjust_weights", { auto_apply: true });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已按确认应用";
      }, "已应用");
    });
    const reportBtn = btn("查看最近报告", async () => {
      await run("evolve", async () => {
        const r = await api("evolve", "report");
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "完成";
      });
    });
    const applyBtn = btn("挖掘并确认写入", async () => {
      if (!confirm("确认把候选规则直接写入经验库（mine_rules auto_apply=true）？")) return;
      await run("evolve", async () => {
        const r = await api("evolve", "mine_rules", { auto_apply: true });
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return "已按确认写入";
      }, "已写入");
    });

    body.appendChild(card("① 进化（默认 auto_apply=false；「确认」类按钮是显式人工确认入口）", [
      toolbar([mineBtn, applyBtn, "spacer", adjustBtn, adjustApplyBtn], { primary: true }),
      toolbar([reportBtn]),
      hint("挖掘候选规则/权重调整默认不落库；确认候选后点「挖掘并确认写入」「调整并确认应用」显式入库（走同一 facade，全程审计）。"),
    ]));
    body.appendChild(card("② 结果", [output]));
  });
}

/* ============================================================
   设置
   ============================================================ */
function vSettings() {
  const body = viewTemplate("v_settings", "设置", "CONFIG", "gear", "system", ({ output }) => {

    body.appendChild(card("① 模块开关（重启生效）", [
      (function () {
        const sw = el("div", "switch-grid");
        api("config", "switches").then(s => {
          sw.innerHTML = "";
          const m = new Map();
          Object.entries(s.switches || {}).forEach(([k, on]) => {
            if (k === "ui") return;  // 关闭即 Web 消失，不展示以免自锁
            const swEl = el("label", "switch" + (on ? " on" : ""));
            swEl.appendChild(el("span", "name", k));
            swEl.appendChild(el("span", "toggle"));
            sw.appendChild(swEl);
            m.set(k, swEl);
            swEl.onclick = () => {
              const now = swEl.classList.contains("on");
              swEl.classList.toggle("on", !now);
              const cfg = { switches: {} };
              m.forEach((node, key) => {
                cfg.switches[key] = node.classList.contains("on");
              });
              api("config", "set_switches", { switches: cfg.switches })
                .then(() => toast("开关已保存", "ok"))
                .catch(e => { swEl.classList.toggle("on", now); toast(e.message, "err"); });
            };
          });
        }).catch(e => toast("加载失败: " + e.message, "err"));
        return sw;
      }()),
    ]));

    body.appendChild(card("② 大模型配置（AI 辅助 / Agent 使用）", [
      (function () {
        const base = input("base_url（如 https://api.deepseek.com/v1）", "wide");
        const key = input("api_key", "wide"); key.type = "password";
        const model = input("model（如 deepseek-v4-flash）");
        api("config", "get_ai").then(c => {
          base.value = c.base_url || ""; key.value = c.api_key || ""; model.value = c.model || "";
        }).catch(e => toast("读取 AI 配置失败: " + e.message, "warn"));
        const saveBtn = el("button", "primary", "保存 AI 配置");
        saveBtn.onclick = async () => {
          await run("cfg_ai", async () => {
            const r = await api("config", "save_ai",
              { base_url: base.value.trim(), api_key: key.value.trim(), model: model.value.trim() });
            if (bizFail(r)) throw new Error("保存失败：" + bizErr(r));
            return "已保存";
          }, "已保存到 config.json");
        };
        return [formRow([["base_url", base], ["model", model]]),
                formRow([["api_key", key]]),
                toolbar([saveBtn])];
      }()),
    ]));

    body.appendChild(card("③ 系统集成", [
      (function () {
        const auto = el("label", "checkbox");
        const cb = el("input"); cb.type = "checkbox";
        auto.appendChild(cb); auto.appendChild(document.createTextNode("开机自启（最小化到托盘）"));
        api("autostart", "is_enabled").then(r => cb.checked = !!r.enabled).catch(() => {});
        cb.onchange = () => api("autostart", "set_enabled", { enabled: cb.checked })
          .then(() => toast("自启已 " + (cb.checked ? "开启" : "关闭"), "ok"))
          .catch(e => { cb.checked = !cb.checked; toast(e.message, "err"); });
        return auto;
      }()),
    ]));

    body.appendChild(card("④ 数据库（观察库 / 经验库）", [
      (function () {
        function reload(kind) {
          api("db", kind === "obs" ? "observations" : "knowledge",
            { limit: kind === "obs" ? 100 : 200 })
            .then(r => {
              output.innerHTML = "";
              output.appendChild(table(r || [], kind === "obs" ? "观察库" : "经验库"));
            })
            .catch(e => toast("加载失败: " + e.message, "err"));
        }
        const wrap = el("div");
        wrap.appendChild(el("div", "toolbar"));
        const row = wrap.firstChild;
        ["obs", "know"].forEach(k => {
          const b = el("button", null, k === "obs" ? "加载观察库" : "加载经验库");
          b.onclick = () => reload(k);
          row.appendChild(b);
        });
        const oid = el("input"); oid.placeholder = "观察条目 ID";
        const kid = el("input"); kid.placeholder = "经验条目 ID";
        const delBtn = el("button", "primary", "删除观察");
        delBtn.onclick = async () => {
          const id = Number(oid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "delete_observation", { oid: id });
            if (bizFail(r)) throw new Error("删除失败：" + bizErr(r));
            return "已删除";
          });
        };
        const delKBtn = el("button", "primary", "删除经验");
        delKBtn.onclick = async () => {
          const id = Number(kid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "delete_knowledge", { kid: id });
            if (bizFail(r)) throw new Error("删除失败：" + bizErr(r));
            return "已删除";
          });
        };
        const offBtn = el("button", null, "停用经验");
        offBtn.onclick = async () => {
          const id = Number(kid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "set_knowledge_enabled", { kid: id, enabled: false });
            if (bizFail(r)) throw new Error("停用失败：" + bizErr(r));
            return "已停用";
          });
        };
        const onBtn = el("button", null, "启用经验");
        onBtn.onclick = async () => {
          const id = Number(kid.value);
          if (!id || id <= 0) { toast("请填写有效 ID", "warn"); return; }
          await run("db", async () => {
            const r = await api("db", "set_knowledge_enabled", { kid: id, enabled: true });
            if (bizFail(r)) throw new Error("启用失败：" + bizErr(r));
            return "已启用";
          });
        };
        wrap.appendChild(el("div", "toolbar"));
        const row2 = wrap.lastChild;
        row2.appendChild(oid); row2.appendChild(delBtn);
        row2.appendChild(kid); row2.appendChild(delKBtn);
        row2.appendChild(offBtn); row2.appendChild(onBtn);
        return wrap;
      }()),
    ]));

    body.appendChild(card("⑤ 结果", [output]));
  });
}

/* ============================================================
   AI 助手（M10 agent 入口，未配置 key 时仅显示提示）
   ============================================================ */
function vAgent() {
  const body = viewTemplate("v_agent", "AI 助手", "M10 · AGENT", "lock", "flow", ({ output }) => {
    const task = textarea("在此输入任务指令（如：列出可疑进程并标记高风险）", "", 3);
    const runBtn = btn("发送给 Agent", async () => {
      await run("agent", async () => {
        const r = await api("agent", "run_task", { task: task.value });
        if (bizFail(r)) throw new Error("Agent 失败：" + bizErr(r));
        output.innerHTML = ""; output.appendChild(jsonBlock(r));
        return r && r.final ? "Agent 完成" : "Agent 完成（无 final 文本）";
      });
    }, false, true);
    body.appendChild(card("① 任务", [task, toolbar([runBtn], { primary: true })]));
    body.appendChild(card("② 结果", [output,
      hint("Agent 命令经独立审核模型 + 人工弹窗审批；高危工具需逐项确认。"),
    ]));
  });
}

/* ============================================================
   连接指示
   ============================================================ */
