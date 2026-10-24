# -*- coding: utf-8 -*-
"""
sec-agent 工具注册表
每个工具是一个可调用函数 (name, description, func)，Agent 通过 ReAct 循环按需调用。
可插拔设计：新增工具只需在 TOOLS 字典里注册一个函数。
"""
import json
import os
from datetime import datetime

import core  # 复用 sec-analyzer 的分析内核（聚类 / LLM / 缓存 / 反馈）

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)


# ---------- 安恒 AAS-Api 真实导出格式适配 ----------
def _detect_rule(rec: dict) -> str:
    """基于请求体/URL 的真实攻击特征检测，生成 rule_id"""
    blob = " ".join(str(rec.get(k) or "") for k in ["reqBody", "reqUrl", "reqLine", "reqHeaderAll"])
    blob_l = blob.lower()
    sql_kw = ["' or", "union select", "extractvalue", "updatexml", "or 1=1", "sleep(", "--", "information_schema", "concat(", "0x"]
    xss_kw = ["<script", "onerror", "javascript:", "<img", "alert(", "<iframe"]
    sens = ["/.env", "/.git", "/wp-admin", "/phpmyadmin", "/config.", "/.ssh", "/passwd", "getshell", "/manager/", "web.config", "actuator"]
    if any(k in blob_l for k in sql_kw):
        return "SQL_INJECTION"
    if any(k in blob_l for k in xss_kw):
        return "XSS_REFLECTED"
    if any(k in blob_l for k in sens):
        return "SCAN_PROBE_SENSITIVE_PATH"
    return "NORMAL_API_CALL"


def _normalize(raw: list) -> list:
    """把 AAS-Api 导出格式映射为分析器内部告警结构；兼容旧 sample 格式"""
    if not raw:
        return []
    first = raw[0]
    is_aas = isinstance(first, dict) and "auditLogId" in first
    normalized = []
    for rec in raw:
        if not isinstance(rec, dict):
            continue
        if is_aas:
            # eventTime 是毫秒时间戳
            et = rec.get("eventTime", 0)
            try:
                event_time = datetime.fromtimestamp(int(et) / 1000).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                event_time = "1970-01-01 00:00:00"
            rule = _detect_rule(rec)
            normalized.append({
                "alert_id": rec.get("auditLogId"),
                "host": rec.get("appName") or rec.get("dip") or "unknown",
                "rule_id": rule,
                "method": rec.get("httpMethod", ""),
                "path_template": rec.get("reqUrl", ""),
                "payload": (rec.get("reqBody") or "") or (rec.get("reqLine") or ""),
                "src_ip": rec.get("sip", ""),
                "dip": rec.get("dip", ""),
                "dport": rec.get("dport", ""),
                "event_time": event_time,
                "rsp_code": rec.get("rspCode", ""),
                "is_alarm": rec.get("isAlarm", 0),
                "req_domain": rec.get("reqDomain", ""),
            })
        else:
            # 兼容旧 sample 格式（已有 rule_id 等字段）
            normalized.append({k: rec.get(k) for k in
                               ["alert_id", "host", "rule_id", "method", "path_template",
                                "payload", "src_ip", "event_time"]})
    return normalized


# ---------- 工具 1：分析告警文件 ----------
def _load_records(filepath: str) -> list:
    """读取告警/审计文件，兼容 JSON 数组和 JSONL（每行一个对象，AAS-Api 导出格式）"""
    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()
    text = text.strip()
    if not text:
        return []
    # 先试 JSON 数组
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        # 回退：按行解析（JSONL）
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records


def analyze_alerts(filepath: str) -> dict:
    """读取告警文件（支持 AAS-Api JSONL 导出格式与内置示例），归一化后跑聚类 + LLM 判定"""
    if not os.path.exists(filepath):
        return {"error": f"文件不存在: {filepath}"}
    raw = _load_records(filepath)
    if not raw:
        return {"error": "文件中没有可解析的记录"}
    alerts = _normalize(raw)
    if not alerts:
        return {"error": "文件中没有可分析的记录"}
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    result = core.analyze(alerts, use_llm=bool(api_key), api_key=api_key)
    result["filepath"] = filepath
    result["source_format"] = "AAS-Api" if isinstance(raw[0], dict) and "auditLogId" in raw[0] else "sample"
    return result


# ---------- 工具 2：查询单条告警明细 ----------
def query_alert_detail(filepath: str, alert_id=None, keyword="") -> dict:
    """在告警文件中定位某条告警，返回原始报文字段"""
    if not os.path.exists(filepath):
        return {"error": f"文件不存在: {filepath}"}
    with open(filepath, "r", encoding="utf-8") as f:
        alerts = json.load(f)
    if alert_id is not None:
        hits = [a for a in alerts if a.get("alert_id") == alert_id]
    elif keyword:
        hits = [a for a in alerts if keyword.lower() in json.dumps(a, ensure_ascii=False).lower()]
    else:
        hits = alerts[:5]
    return {"count": len(hits), "alerts": hits}


# ---------- 工具 3：生成分析报告 ----------
def generate_report(result: dict, format: str = "html") -> dict:
    """把分析结果渲染成 HTML 报告，落盘到 reports/ 目录，返回路径"""
    report_dir = os.path.join(DATA_DIR, "reports")
    os.makedirs(report_dir, exist_ok=True)
    total = result.get("total_alerts", 0)
    attack = result.get("attack_count", 0)
    fp = result.get("fp_count", 0)
    s1 = result.get("stage1_results", {})
    src_fmt = result.get("source_format", "unknown")

    if s1:
        rows = "".join(
            f"<tr><td>{k}</td><td>{v['verdict']}</td><td>{v['count']}</td><td>{v['reasons']}</td></tr>"
            for k, v in s1.items()
        )
    else:
        rows = "<tr><td colspan='4'>无聚类结果</td></tr>"

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Agent 分析报告</title>
<style>body{{font-family:-apple-system,'Microsoft YaHei',sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#2c3e50}}
h1{{font-size:20px;border-bottom:2px solid #1f3a5f;padding-bottom:10px}}
.meta{{color:#888;font-size:13px;margin:16px 0}}
.summary{{display:flex;gap:20px;margin:20px 0}}
.summary div{{flex:1;padding:16px;border-radius:8px;background:#f8f9fa;text-align:center}}
.summary b{{font-size:24px;display:block}}
.attack b{{color:#c0392b}} .fp b{{color:#16a34a}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th,td{{border:1px solid #e5e7eb;padding:8px 10px;text-align:left;font-size:13px}}
th{{background:#fafbfc}}</style>
</head><body><h1>API 审计告警分析报告</h1>
<p class="meta">数据源：{result.get('filepath','')} · 格式：{src_fmt} · 分析时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="summary">
  <div>总告警<br><b>{total}</b></div>
  <div class="attack">真实攻击<br><b>{attack}</b></div>
  <div class="fp">误报<br><b>{fp}</b></div>
</div>
<h2 style="font-size:16px;color:#1f3a5f">聚类判定明细</h2>
<table><tr><th>规则@主机/路径</th><th>结论</th><th>数量</th><th>判定理由</th></tr>{rows}</table>
<p class="meta" style="margin-top:32px">本报告由 sec-agent 基于 LangGraph 自动生成</p>
</body></html>"""
    path = os.path.join(report_dir, "report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return {"path": path, "attack": attack, "fp": fp, "total": total}


# ---------- 工具 4：发送结果通知（模拟 + 可替换为钉钉/飞书 webhook）----------
def notify(message: str, channel: str = "console") -> dict:
    """把 Agent 的结论推送到指定渠道。默认 console；预留 webhook 扩展"""
    if channel == "console":
        print(f"[sec-agent 通知] {message}")
    elif channel.startswith("http"):
        # 预留：未来接钉钉/飞书 webhook 只需在这里发 HTTP 请求
        pass
    return {"channel": channel, "delivered": True, "message": message}


# ---------- 工具 5：能力说明 ----------
def list_capabilities() -> dict:
    """返回 Agent 支持的能力清单，用于回答「你能做什么」"""
    caps = [
        {"能力": "告警批量分析", "触发": "分析告警/研判告警/检查告警", "说明": "读取告警文件，两阶段聚类 + LLM 判定误报与真实攻击"},
        {"能力": "生成分析报告", "触发": "生成报告/导出报告/汇总", "说明": "把分析结果渲染成 HTML 报告，可直接在页面查看"},
        {"能力": "告警明细查询", "触发": "查询某条告警/SQL注入/关键词", "说明": "在告警文件中按关键词或告警ID定位明细"},
        {"能力": "结果通知", "触发": "通知我/发送结果/提醒", "说明": "把研判结论投递到指定渠道（默认控制台，可接 webhook）"},
        {"能力": "攻击事件汇总", "触发": "汇总攻击事件/统计", "说明": "按来源IP时序关联，归并攻击事件"},
    ]
    return {"capabilities": caps, "count": len(caps)}


# ============ 工具注册表 ============
TOOLS = [
    {"name": "analyze_alerts", "description": "分析告警文件，输入文件路径，输出聚类+判定结果",
     "func": analyze_alerts, "params": {"filepath": "string"}},
    {"name": "query_alert_detail", "description": "查询告警文件中的某条告警明细，输入文件路径和关键词或告警ID",
     "func": query_alert_detail, "params": {"filepath": "string", "keyword": "string", "alert_id": "integer"}},
    {"name": "generate_report", "description": "把分析结果生成 HTML 报告，输入分析结果对象，输出报告路径",
     "func": generate_report, "params": {"result": "object"}},
    {"name": "notify", "description": "发送结果通知，输入消息文本，输出投递状态",
     "func": notify, "params": {"message": "string", "channel": "string"}},
    {"name": "list_capabilities", "description": "返回 Agent 的能力清单，回答用户问'你能做什么'",
     "func": list_capabilities, "params": {}},
]


def get_tool(name: str):
    for t in TOOLS:
        if t["name"] == name:
            return t["func"]
    return None


def tool_schema_text() -> str:
    """给 LLM 看的工具说明"""
    lines = []
    for t in TOOLS:
        lines.append(f"- {t['name']}({json.dumps(t['params'], ensure_ascii=False)}): {t['description']}")
    return "\n".join(lines)
