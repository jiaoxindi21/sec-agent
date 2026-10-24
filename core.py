# -*- coding: utf-8 -*-
"""
SecInsight-Pro 核心引擎
- Stage1 聚类：host + rule_id + path_template
- Stage2 二次聚合：同一 src_ip 时间窗内的告警归为一次攻击事件
- LLM 判定：DeepSeek API（Mock 模式可跑）
- 缓存：payload hash -> 判定结果，避免重复调用
- Few-shot 反馈：人工复核结果入库，下次自动作为示例
"""
import json
import hashlib
import os
from collections import defaultdict
from datetime import datetime, timedelta

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

CACHE_FILE = os.path.join(DATA_DIR, "cache.json")
FEEDBACK_FILE = os.path.join(DATA_DIR, "feedback.json")

CONFIG = {
    "sample_size": 3,
    "vote_rounds": 2,
    "consensus_ratio": 0.75,
    "attack_window_minutes": 30,   # Stage2: 同一 src_ip 30 分钟内告警归为一次事件
    "malicious_ip_cidrs": ["1.1.1.1"],
}


def _load_json(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ============ 缓存层 ============
def get_cache():
    return _load_json(CACHE_FILE, {})


def cache_key(alert: dict) -> str:
    raw = f"{alert['rule_id']}|{alert.get('payload','')}|{alert['path_template']}"
    return hashlib.md5(raw.encode()).hexdigest()


def lookup_cache(alert: dict):
    return get_cache().get(cache_key(alert))


def write_cache(alert: dict, result: dict):
    cache = get_cache()
    cache[cache_key(alert)] = {"result": result, "ts": datetime.now().isoformat()}
    _save_json(CACHE_FILE, cache)


# ============ Few-shot 反馈库 ============
def get_feedback():
    return _load_json(FEEDBACK_FILE, [])


def add_feedback(alert: dict, human_verdict: str):
    """人工复核结果加入 Few-shot 库"""
    fb = get_feedback()
    fb.append({
        "alert": {k: alert.get(k) for k in ["rule_id", "path_template", "payload", "src_ip"]},
        "human_verdict": human_verdict,
        "ts": datetime.now().isoformat(),
    })
    _save_json(FEEDBACK_FILE, fb)


def few_shot_examples(rule_id: str, n: int = 3):
    """取同规则的历史人工判定作为 Few-shot 示例"""
    fb = get_feedback()
    related = [x for x in fb if x["alert"]["rule_id"] == rule_id]
    return related[-n:]


# ============ Stage1: 业务字段聚类 ============
def cluster_stage1(alerts: list) -> dict:
    clusters = defaultdict(list)
    for a in alerts:
        key = (a["host"], a["rule_id"], a["path_template"])
        clusters[key].append(a)
    return clusters


# ============ Stage2: payload 语义聚类（n-gram Jaccard 相似度）============
def _char_ngrams(text: str, n: int = 2) -> set:
    """把字符串切成字符 n-gram 集合，作为本地 embedding 的替代向量"""
    text = text.lower().strip()
    if len(text) < n:
        return {text}
    return {text[i:i+n] for i in range(len(text) - n + 1)}


def jaccard_similarity(a: str, b: str) -> float:
    """两组字符 n-gram 的 Jaccard 相似度，等价于集合余弦相似度"""
    sa, sb = _char_ngrams(a), _char_ngrams(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def cluster_stage2_semantic(group_alerts: list, threshold: float = 0.55) -> list:
    """
    在 Stage1 组内，按 payload 语义相似度二次聚合。
    把 ' OR 1=1-- / ' OR 2=2-- / ' OR '3'='3 这类变体归为同一类。
    threshold: 相似度阈值，0.55 意味着字符 bigram 重合度 > 55% 就算同类。
    """
    clusters = []  # 每个元素是一个 list[alert]
    for a in group_alerts:
        payload = a.get("payload", "")
        placed = False
        for cluster in clusters:
            rep_payload = cluster[0].get("payload", "")
            if jaccard_similarity(payload, rep_payload) >= threshold:
                cluster.append(a)
                placed = True
                break
        if not placed:
            clusters.append([a])
    return clusters


# ============ Stage2: 攻击事件时序关联 ============
def correlate_attacks(alerts: list) -> list:
    """同一 src_ip 在 attack_window 分钟内的告警归为一次攻击事件"""
    by_ip = defaultdict(list)
    for a in alerts:
        by_ip[a["src_ip"]].append(a)

    events = []
    for ip, items in by_ip.items():
        items.sort(key=lambda x: x["event_time"])
        current_event = []
        last_t = None
        for a in items:
            t = datetime.strptime(a["event_time"], "%Y-%m-%d %H:%M:%S")
            if last_t and (t - last_t).total_seconds() > CONFIG["attack_window_minutes"] * 60:
                events.append({"src_ip": ip, "alerts": current_event})
                current_event = []
            current_event.append(a)
            last_t = t
        if current_event:
            events.append({"src_ip": ip, "alerts": current_event})
    return events


# ============ LLM 判定 ============
def judge_alert(alert: dict, use_llm: bool = None, api_key: str = "") -> dict:
    """先查缓存，缓存未命中才调 LLM。
    use_llm=None 时自动检测环境变量 DEEPSEEK_API_KEY，有 key 就走真 LLM。
    """
    cached = lookup_cache(alert)
    if cached:
        return {**cached["result"], "from_cache": True}

    if use_llm is None:
        api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        use_llm = bool(api_key)

    if not use_llm:
        result = _judge_mock(alert)
    else:
        result = _judge_llm(alert, api_key)

    write_cache(alert, result)
    return {**result, "from_cache": False}


def _judge_mock(alert: dict) -> dict:
    payload = alert.get("payload", "")
    rule = alert["rule_id"]
    attack_kw = ["'", "UNION", "SELECT", "<script", "onerror", "--", " OR "]

    # Few-shot 反馈优先：如果历史上人工判过这个 rule 类似的，参考历史结论
    examples = few_shot_examples(rule)
    if examples:
        last = examples[-1]["human_verdict"]
        return {"is_false_positive": last == "误报",
                "risk_level": "low" if last == "误报" else "high",
                "reason": f"参考人工历史判定: {last}"}

    if rule == "SCAN_PROBE":
        return {"is_false_positive": False, "risk_level": "medium",
                "reason": "访问敏感路径，疑似扫描器"}
    if any(k.lower() in payload.lower() for k in attack_kw):
        return {"is_false_positive": False, "risk_level": "high",
                "reason": "payload 含攻击特征"}
    return {"is_false_positive": True, "risk_level": "info",
            "reason": "正常业务输入"}


def _judge_llm(alert: dict, api_key: str) -> dict:
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    examples = few_shot_examples(alert["rule_id"])
    example_text = ""
    for ex in examples:
        example_text += f"\n历史案例: {ex['alert']['payload']} => 人工判定: {ex['human_verdict']}\n"

    prompt = f"""你是安全分析师。判断告警是否误报。只返回JSON:
{{"is_false_positive": true/false, "risk_level": "high/medium/low/info", "reason": "一句话"}}
{example_text}
告警: rule={alert['rule_id']}, path={alert['path_template']}, payload={alert['payload']}, src_ip={alert['src_ip']}"""

    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.3,
    )
    return json.loads(resp.choices[0].message.content)


# ============ 完整分析管线 ============
def analyze(alerts: list, use_llm: bool = False, api_key: str = "") -> dict:
    # Stage1
    s1 = cluster_stage1(alerts)
    stage1_results = {}
    for key, group in s1.items():
        samples = group[:CONFIG["sample_size"]]
        fp_votes = 0
        reasons = set()
        for _ in range(CONFIG["vote_rounds"]):
            for a in samples:
                r = judge_alert(a, use_llm, api_key)
                if r["is_false_positive"]:
                    fp_votes += 1
                reasons.add(r["reason"])
        total = len(samples) * CONFIG["vote_rounds"]
        fp_ratio = fp_votes / total if total else 0
        verdict = "误报" if fp_ratio >= CONFIG["consensus_ratio"] else "真实告警"
        stage1_results[f"{key[1]}@{key[0]}{key[2]}"] = {
            "verdict": verdict, "fp_ratio": round(fp_ratio, 2),
            "reasons": list(reasons)[:2], "count": len(group),
        }

    # Stage2: 时序关联
    events = correlate_attacks(alerts)

    # 统计攻击/误报数量（按聚类判定结果累加）
    attack_count = sum(v["count"] for v in stage1_results.values() if v["verdict"] == "真实告警")
    fp_count = sum(v["count"] for v in stage1_results.values() if v["verdict"] == "误报")

    return {
        "total_alerts": len(alerts),
        "attack_count": attack_count,
        "fp_count": fp_count,
        "stage1_clusters": len(s1),
        "stage1_results": stage1_results,
        "attack_events": [{"src_ip": e["src_ip"], "count": len(e["alerts"]),
                           "rules": list({a["rule_id"] for a in e["alerts"]})} for e in events],
        "cache_hit": len(get_cache()),
        "feedback_count": len(get_feedback()),
    }
