# -*- coding: utf-8 -*-
"""
sec-agent 核心引擎 —— 基于 LangGraph 的 ReAct Agent

真实 Agent 结构（StateGraph + 条件边）：
    START → planner → tool_executor ──(还有下一步)→ planner ──循环──┐
                          │                                            │
                          └────(LLM 判定 FINISH)──→ END ◄────────────┘

每个循环：
    planner       用 LLM 决策「下一步调用哪个工具」或「任务完成」(Thought + Action)
    tool_executor 执行工具，把结果作为 Observation 写回 state
    route         条件边：未完成 → 回到 planner；完成 → END

这比一次性规划步骤的"伪 Agent"更接近业界真实实现（带状态、checkpoint、条件分支）。
"""
import json
import os
from typing import TypedDict

from langgraph.graph import StateGraph, START, END

import tools

MAX_STEPS = 8

# ---------- 状态定义 ----------
class AgentState(TypedDict):
    task: str
    filepath: str
    messages: list          # 给 LLM 的对话历史（含历次 Observation）
    steps: list             # 已执行轨迹，供前端展示
    step_count: int
    pending_action: str     # planner 决策出的工具名
    pending_args: dict
    last_observation: str
    final_text: str


class Agent:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self.trace = []
        self._llm_client = None

    # ---------- LLM 对话（无 key 时返回 None，走规则决策）----------
    def _llm(self, messages: list, temperature: float = 0.3) -> dict:
        from openai import OpenAI
        if self._llm_client is None:
            self._llm_client = OpenAI(api_key=self.api_key, base_url="https://api.deepseek.com")
        resp = self._llm_client.chat.completions.create(
            model="deepseek-chat", messages=messages,
            response_format={"type": "json_object"}, temperature=temperature,
        )
        return json.loads(resp.choices[0].message.content)

    # ---------- planner 节点：决策下一步 ----------
    def _planner(self, state: AgentState) -> dict:
        task = state["task"]
        messages = state["messages"]
        schema = tools.tool_schema_text()

        if self.api_key:
            try:
                system = (
                    "你是安全分析 Agent 的规划器，负责决策『下一步』。\n"
                    "可用工具：\n" + schema + "\n"
                    "必须只返回 JSON 二选一：\n"
                    '{"finish": true, "summary": "一句话总结结果"}\n'
                    ' 或 {"tool": "工具名", "args": {...}}\n'
                    "规则：\n"
                    "- 分析类任务先调 analyze_alerts，再视任务调 generate_report / notify\n"
                    "- 若上一 Observation 显示结果已就绪、不需要再调工具，返回 finish\n"
                    "- analyze_alerts 的 filepath 取任务的告警文件路径"
                )
                r = self._llm([{"role": "system", "content": system}] + messages)
                if r.get("finish"):
                    return {"pending_action": "FINISH", "pending_args": {}, "final_text": r.get("summary", "任务完成。")}
                tool = r.get("tool", "list_capabilities")
                args = r.get("args", {})
                # analyze_alerts 必须有文件路径；LLM 留空时强制用任务文件或默认示例
                if tool == "analyze_alerts":
                    if not args.get("filepath"):
                        args["filepath"] = state["filepath"] or "sample_alerts.json"
                return {"pending_action": tool, "pending_args": args}
            except Exception:
                pass  # 降级到规则决策

        # 规则决策（无 key / LLM 失败）：按任务类型推进
        return self._rule_planner(state)

    def _answer_question(self, task: str) -> str:
        """对话/澄清类问题的回答（规则壳兜底，真 Agent 由 LLM 回答）"""
        t = task
        if any(k in t for k in ["多个", "多选", "批量", "几文件", "几个"]):
            return "可以，我支持上传多个文件。点 📎 可多选，会把所有文件合并后统一聚类、判定、生成报告。"
        if any(k in t for k in ["是不是真", "真实 agent", "真 agent", "还是壳", "写死"]):
            return "我基于 LangGraph StateGraph 实现 ReAct 循环（planner→tool_executor→条件边），规划决策由 LLM 驱动。如果你没配 DeepSeek key，规划会退化为规则匹配——配了 key 就是真正的 LLM 每步决策。"
        if any(k in t for k in ["什么技术", "技术栈", "用什么做的", "什么框架"]):
            return "技术栈：LangGraph（StateGraph ReAct 循环）+ DeepSeek LLM + Flask。工具注册表可插拔，含 analyze_alerts / generate_report / query_alert_detail / notify / list_capabilities。"
        if any(k in t for k in ["能不能", "可以吗", "是不是", "怎么用", "如何", "为什么", "？", "?", "能做什么", "能上传"]):
            return ("我是基于 LangGraph 的告警自动研判 Agent。我可以：分析告警文件、生成 HTML 报告、查询告警明细、汇总攻击事件、发送结果通知。"
                    "也支持上传多个文件合并分析。你可以对我说『分析告警并生成报告』或『分析上传的文件并汇总』。")
        return ""

    def _rule_planner(self, state: AgentState) -> dict:
        task = state["task"]
        target = state["filepath"] or "sample_alerts.json"
        done = [s["action"] for s in state["steps"]]

        # 对话/澄清类问题优先直接回答，不硬套工具
        if not state["steps"]:
            ans = self._answer_question(task)
            if ans:
                return {"pending_action": "FINISH", "pending_args": {}, "final_text": ans}

        if "list_capabilities" not in done and any(k in task for k in ["功能", "能做什么", "会什么", "能力", "你能"]):
            return {"pending_action": "list_capabilities", "pending_args": {}}
        if "analyze_alerts" not in done and any(k in task for k in ["分析", "研判", "检查", "告警", "analyze"]):
            return {"pending_action": "analyze_alerts", "pending_args": {"filepath": target}}
        if "analyze_alerts" in done and any(k in task for k in ["报告", "汇总", "report", "export"]) and "generate_report" not in done:
            return {"pending_action": "generate_report", "pending_args": {"result": "__PREV__"}}
        if "generate_report" in done and any(k in task for k in ["通知", "发送", "提醒", "notify"]) and "notify" not in done:
            return {"pending_action": "notify", "pending_args": {"message": "分析完成，请查看报告", "channel": "console"}}
        if "query_alert_detail" not in done and any(k in task for k in ["查询", "定位", "sql", "注入", "keyword"]):
            return {"pending_action": "query_alert_detail", "pending_args": {"filepath": target, "keyword": task}}
        return {"pending_action": "FINISH", "pending_args": {}, "final_text": "任务执行完成。"}

    # ---------- tool_executor 节点：执行工具 ----------
    def _tool_executor(self, state: AgentState) -> dict:
        action = state["pending_action"]
        if action == "FINISH":
            return {}
        func = tools.get_tool(action)
        args = dict(state["pending_args"])
        if "__PREV__" in args.values() and state.get("last_observation"):
            for k, v in args.items():
                if v == "__PREV__":
                    args[k] = state.get("last_observation")
        try:
            obs = func(**args)
        except Exception as e:
            obs = {"error": str(e)}

        # 把本轮 Thought / Action / Observation 追加进 messages 和 steps
        step = {"action": action, "args": args, "observation": obs}
        steps = state["steps"] + [step]
        messages = state["messages"] + [{
            "role": "user",
            "content": f"上一步调用工具 {action}，返回：{json.dumps(obs, ensure_ascii=False, default=str)}",
        }]
        return {"steps": steps, "messages": messages,
                "last_observation": obs, "step_count": state["step_count"] + 1}

    # ---------- 条件边：是否结束 ----------
    def _route(self, state: AgentState) -> str:
        if state["pending_action"] == "FINISH":
            return "finish"
        if state["step_count"] >= MAX_STEPS:
            return "finish"
        return "continue"

    # ---------- 构建并运行 LangGraph ----------
    def _build_graph(self):
        g = StateGraph(AgentState)
        g.add_node("planner", self._planner)
        g.add_node("tool_executor", self._tool_executor)
        g.add_edge(START, "planner")
        g.add_conditional_edges(
            "planner", self._route,
            {"continue": "tool_executor", "finish": END},
        )
        g.add_edge("tool_executor", "planner")
        return g.compile()

    def run(self, task: str, filepath: str = "") -> dict:
        initial = {
            "task": task,
            "filepath": filepath,
            "messages": [{"role": "user", "content": f"任务：{task}"}] + self._context(),
            "steps": [],
            "step_count": 0,
            "pending_action": "",
            "pending_args": {},
            "last_observation": None,
            "final_text": "",
        }
        graph = self._build_graph()
        result = graph.invoke(initial)
        final = self._summarize(result.get("last_observation"), result.get("final_text"), result.get("steps"))
        return {
            "task": task,
            "steps": result.get("steps", []),
            "final": final,
            "used_llm": bool(self.api_key),
            "graph": "LangGraph StateGraph",
        }

    def _context(self) -> list:
        """给 planner 的系统上下文：任务数据概要"""
        return []

    def _summarize(self, last_obs, final_text, steps=None):
        # 从已执行步骤里找最有价值的结果（report > analyze > query > capabilities）
        best = None
        if steps:
            for s in reversed(steps):
                o = s.get("observation")
                if isinstance(o, dict) and o.get("path"):
                    best = ("report", o); break
                if isinstance(o, dict) and "total_alerts" in o:
                    best = ("analyze", o); break
                if isinstance(o, dict) and o.get("alerts"):
                    best = ("query", o); break
                if isinstance(o, dict) and o.get("capabilities"):
                    best = ("capabilities", o); break
        kind, obs = best if best else (None, last_obs)
        if kind == "report":
            return {"text": f"报告已生成：{obs['path']}，攻击 {obs.get('attack',0)} 条，误报 {obs.get('fp',0)} 条。",
                    "data": {"report_path": obs["path"], "attack": obs.get("attack",0), "fp": obs.get("fp",0)}, "kind": "report"}
        if kind == "analyze":
            return {"text": f"分析完成：共 {obs['total_alerts']} 条告警，归为 {obs.get('stage1_clusters',0)} 组，检出 {len(obs.get('attack_events',[]))} 个攻击事件。",
                    "data": obs, "kind": "analyze"}
        if kind == "query":
            hits = obs["alerts"]
            head = "\n".join(f"- [{a.get('alert_id')}] {a.get('rule_id')} {a.get('path_template')} src={a.get('src_ip')}" for a in hits[:5])
            return {"text": f"查询到 {obs.get('count', len(hits))} 条匹配告警：\n{head}", "data": obs, "kind": "query"}
        if kind == "capabilities":
            lines = [f"- {c['能力']}: {c['说明']}（触发词：{c['触发']}）" for c in obs["capabilities"]]
            return {"text": "我可以帮你完成以下任务：\n" + "\n".join(lines), "data": obs, "kind": "capabilities"}
        return {"text": final_text or "任务完成。", "data": last_obs}
