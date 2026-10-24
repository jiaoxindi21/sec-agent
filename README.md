# sec-agent

> 告警自动研判 Agent —— 基于 LangGraph StateGraph 的 ReAct 自主分析工具

## 概述

sec-agent 是一个能"自主干活"的 Agent：接收自然语言任务后，自行规划步骤、调用工具、执行分析并产出结果。核心是 **LangGraph StateGraph 驱动的 ReAct 循环（Thought → Action → Observation）**，配合可插拔的工具注册表。

**关键设计**：规划器（Planner）由 LLM 每步实时决策该调用哪个工具、是否结束；无有效 API Key 时自动降级为规则规划器兜底，保证离线可运行。

**技术栈**：Python / Flask / LangGraph（StateGraph）/ ReAct / DeepSeek LLM
**独立端口**：`8081`（与 sec-analyzer 的 8080 并行运行）

---

## 核心能力

| 能力 | 说明 |
|---|---|
| LLM 任务规划 | Planner 由 DeepSeek 实时决策工具调用序列；无 Key 时规则规划兜底 |
| LangGraph 状态机 | StateGraph + 条件边循环，天然支持多步工具编排 |
| 工具注册表 | `analyze_alerts` / `query_alert_detail` / `generate_report` / `notify` / `list_capabilities`，新增工具只需注册一个函数 |
| 多文件合并分析 | 支持一次上传多个 JSON/JSONL，合并后统一聚类判定 |
| 真实数据适配 | 兼容安恒 AAS-Api 导出的 JSONL 审计日志，自动映射字段并做攻击特征检测 |
| 结果可视化 | 统计卡片 + 聚类判定明细表 + 攻击事件时序 + HTML 报告内联预览 |
| 结果汇报 | 自动生成 HTML 报告，可扩展通知到钉钉/飞书 webhook |

---

## 快速部署

```bash
pip install flask openai langgraph
export DEEPSEEK_API_KEY="sk-..."   # 建议配置；不配则走规则规划器（非 LLM 决策）
python app.py                       # 访问 http://localhost:8081
```

> **Key 安全**：真实 key 请放在项目根目录 `.env`，或通过环境变量注入。切勿硬编码进源码。

---

## 项目结构

```
sec-agent/
├── app.py        # Flask 入口（8081），.env 加载、多文件合并
├── agent.py      # LangGraph StateGraph + ReAct 循环 + Planner
├── tools.py      # 工具注册表（可插拔）+ 真实 AAS 数据适配
├── core.py       # 复用分析内核（两阶段聚类 / LLM / 缓存 / 反馈）
├── templates/    # Claude 风格对话工作台
└── sample_alerts.json
```

---

## LangGraph ReAct 工作流

```
用户任务 "分析告警并生成报告"
    ↓
Planner(LLM)  决策 → 调用 analyze_alerts
    ↓
tool_executor 执行 → Observation 聚类结果
    ↓
条件边: continue → Planner 再决策 → generate_report
    ↓
Planner  决策 finish → END → 汇总
```

节点：`planner → (data) → tool_executor`，条件边 `continue → tool_executor / finish → END`，最大循环步数 `MAX_STEPS`。

---

## 工具扩展

在 `tools.py` 的 `TOOLS` 列表追加一个函数即可：

```python
def my_tool(arg): ...
TOOLS.append({"name":"my_tool", "description":"...", "func": my_tool, "params":{...}})
```

---

## 许可证

内部工具，仅限部门内使用。
