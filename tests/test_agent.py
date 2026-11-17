# -*- coding: utf-8 -*-
"""sec-agent 工作流单元测试：不依赖网络，走规则规划器验证 Agent 闭环。"""
import os
import tempfile
import unittest

import agent
import tools


class ToolRegistryTest(unittest.TestCase):
    def test_lookup_and_schema(self):
        self.assertIsNotNone(tools.get_tool("analyze_alerts"))
        self.assertIsNone(tools.get_tool("non_existent"))
        schema = tools.tool_schema_text()
        self.assertIn("analyze_alerts", schema)
        self.assertIn("generate_report", schema)

    def test_register_tool_runtime(self):
        def dummy(x: str):
            return {"x": x}
        tools.register_tool("dummy", dummy, "测试工具", {"x": "string"})
        self.assertEqual(tools.get_tool("dummy")("ok"), {"x": "ok"})
        self.assertIn("dummy", tools.tool_schema_text())
        del tools.TOOLS["dummy"]  # 清理，避免污染其他用例

    def test_query_supports_jsonl(self):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
        tmp.write('{"alert_id": 1, "rule_id": "SQL"}\n{"alert_id": 2, "rule_id": "XSS"}\n')
        tmp.close()
        try:
            r = tools.query_alert_detail(tmp.name, keyword="SQL")
            self.assertEqual(r["count"], 1)
        finally:
            os.unlink(tmp.name)


class AgentFlowTest(unittest.TestCase):
    def test_context_injects_data_summary(self):
        a = agent.Agent()  # 无 key -> 规则模式
        ctx = a._context("sample_alerts.json")
        self.assertEqual(len(ctx), 1)
        self.assertIn("数据概要", ctx[0]["content"])
        self.assertIn("规则分布", ctx[0]["content"])

    def test_full_flow_without_llm(self):
        a = agent.Agent()
        result = a.run("分析告警并生成报告", "sample_alerts.json")
        actions = [s["action"] for s in result["steps"]]
        self.assertEqual(actions, ["analyze_alerts", "generate_report"])
        self.assertEqual(result["final"]["kind"], "report")
        self.assertFalse(result["used_llm"])

    def test_prev_placeholder_replaced(self):
        a = agent.Agent()
        state = {
            "pending_action": "generate_report",
            "pending_args": {"result": "__PREV__"},
            "last_observation": {"total_alerts": 5, "attack_count": 2, "fp_count": 3},
            "steps": [], "messages": [], "step_count": 0,
        }
        out = a._tool_executor(state)
        self.assertEqual(out["steps"][0]["args"]["result"]["total_alerts"], 5,
                         "__PREV__ 应被替换为上一轮 observation")

    def test_route_stops_at_max_steps(self):
        a = agent.Agent()
        self.assertEqual(a._route({"pending_action": "analyze_alerts", "step_count": 0}), "continue")
        self.assertEqual(a._route({"pending_action": "FINISH", "step_count": 0}), "finish")
        self.assertEqual(a._route({"pending_action": "analyze_alerts", "step_count": 8}), "finish")


if __name__ == "__main__":
    unittest.main()
