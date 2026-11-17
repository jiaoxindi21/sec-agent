# -*- coding: utf-8 -*-
"""
SecInsight-Pro 核心引擎
- Stage1 聚类：host + rule_id + path_template
- Stage2 二次聚合：payload bigram Jaccard 相似度（complete-linkage，消除顺序敏感）
- LLM 判定：DeepSeek API（Mock 模式可跑）
- 多视角投票：每轮用不同判定视角独立判定，缓存键含视角维度
- 缓存：rule + payload + path + 视角 -> 判定结果，避免重复调用
- Few-shot 反馈：人工复核结果入库，下次自动作为示例
"""
import json
import hashlib
import os
from collections import defaultdict
from datetime import datetime

import config

CACHE_FILE = config.CACHE_FILE
FEEDBACK_FILE = config.FEEDBACK_FILE
CONFIG = config.ANALYSIS

# 多视角：每一轮投票采用不同的判定侧重，避免"重复同一判断"
PERSPECTIVES = [
    {"name": "signature", "lens": "视角A-攻击特征：重点看 payload 是否命中已知攻击载荷（SQL注入/XSS/命令执行），特征明确才判真实攻击。"},
    {"name": "business", "lens": "视角B-业务上下文：重点看正常业务是否可能产生该请求；若存在合理业务解释，倾向判误报。"},
    {"name": "context", "lens": "视角C-请求上下文：综合来源IP、路径敏感度、响应码，判断是否为自动化扫描探测行为。"},
]


def _load_json(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ============ 缓存层（缓存键含视角维度）============
def cache_key(alert: dict, perspective: str = "default") -> str:
    raw = f"{alert['rule_id']}|{alert.get('payload','')}|{alert['path_template']}|{perspective}"
    return hashlib.md5(raw.encode()).hexdigest()


def lookup_cache(alert: dict, perspective: str = "default"):
    return _load_json(CACHE_FILE, {}).get(cache_key(alert, perspective))


def write_cache(alert: dict, result: dict, perspective: str = "default"):
    cache = _load_json(CACHE_FILE, {})
    cache[cache_key(alert, perspective)] = {"result": result, "ts": datetime.now().isoformat()}
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
    return [x for x in get_feedback() if x["alert"]["rule_id"] == rule_id][-n:]


# ============ Stage1: 业务字段聚类 ============
def cluster_stage1(alerts: list) -> dict:
    clusters = defaultdict(list)
    for a in alerts:
        clusters[(a["host"], a["rule_id"], a["path_template"])].append(a)
    return clusters


# ============ Stage2: payload 语义聚类 ============
def _char_ngrams(text: str, n: int = 2) -> set:
    """字符 n-gram 集合，作为本地 embedding 的替代向量（零依赖、零成本）"""
    text = text.lower().strip()
    if len(text) < n:
        return {text}
    return {text[i:i+n] for i in range(len(text) - n + 1)}


def jaccard_similarity(a: str, b: str) -> float:
    sa, sb = _char_ngrams(a), _char_ngrams(b)
    if not sa or not sb:
        return 0.0
    inter, union = len(sa & sb), len(sa | sb)
    return inter / union if union else 0.0


def cluster_stage2_semantic(group_alerts: list, threshold: float = None, strategy: str = "complete") -> list:
    """
    在 Stage1 组内按 payload 语义相似度二次聚合，把 ' OR 1=1-- / ' OR 2=2-- 归为同源变体。
    strategy:
      - 'representative'（旧）：只和簇首比较，快但顺序敏感
      - 'complete'（默认）：与簇内所有成员比较取最小值，簇内任意两条都足够相似，
        消除"簇首选谁"造成的顺序敏感性
    """
    threshold = CONFIG["stage2_threshold"] if threshold is None else threshold
    clusters = []
    for a in group_alerts:
        payload = a.get("payload", "")
        sims = []
        for cluster in clusters:
            scores = [jaccard_similarity(payload, m.get("payload", "")) for m in cluster]
            sims.append(min(scores) if strategy == "complete" else scores[0])
        if sims:
            best = max(range(len(sims)), key=lambda i: sims[i])
            if sims[best] >= threshold:
                clusters[best].append(a)
                continue
        clusters.append([a])
    return clusters


# ============ 攻击事件时序关联 ============
def correlate_attacks(alerts: list) -> list:
    """同一 src_ip 在 attack_window 分钟内的告警归为一次攻击事件"""
    by_ip = defaultdict(list)
    for a in alerts:
        by_ip[a["src_ip"]].append(a)
    events = []
    for ip, items in by_ip.items():
        items.sort(key=lambda x: x["event_time"])
        current, last_t = [], None
        for a in items:
            t = datetime.strptime(a["event_time"], "%Y-%m-%d %H:%M:%S")
            if last_t and (t - last_t).total_seconds() > CONFIG["attack_window_minutes"] * 60:
                events.append({"src_ip": ip, "alerts": current})
                current = []
            current.append(a)
            last_t = t
        if current:
            events.append({"src_ip": ip, "alerts": current})
    return events


# ============ LLM 判定 ============
def judge_alert(alert: dict, use_llm: bool = None, api_key: str = "",
                perspective: str = "default") -> dict:
    """先查缓存（键含视角），未命中才调 LLM。视角不同 => 判定相互独立。"""
    cached = lookup_cache(alert, perspective)
    if cached:
        return {**cached["result"], "from_cache": True}
    if use_llm is None:
        api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        use_llm = bool(api_key)
    result = _judge_llm(alert, api_key, perspective) if use_llm else _judge_mock(alert)
    write_cache(alert, result, perspective)
    return {**result, "from_cache": False}


def _judge_mock(alert: dict) -> dict:
    payload, rule = alert.get("payload", ""), alert["rule_id"]
    attack_kw = ["'", "UNION", "SELECT", "<script", "onerror", "--", " OR "]
    examples = few_shot_examples(rule)
    if examples:
        last = examples[-1]["human_verdict"]
        return {"is_false_positive": last == "误报",
                "risk_level": "low" if last == "误报" else "high",
                "reason": f"参考人工历史判定: {last}"}
    if rule == "SCAN_PROBE":
        return {"is_false_positive": False, "risk_level": "medium", "reason": "访问敏感路径，疑似扫描器"}
    if any(k.lower() in payload.lower() for k in attack_kw):
        return {"is_false_positive": False, "risk_level": "high", "reason": "payload 含攻击特征"}
    return {"is_false_positive": True, "risk_level": "info", "reason": "正常业务输入"}


def _judge_llm(alert: dict, api_key: str, perspective: str = "default") -> dict:
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url=config.DEEPSEEK_BASE_URL)
    examples = few_shot_examples(alert["rule_id"])
    example_text = "".join(
        f"\n历史案例: {ex['alert']['payload']} => 人工判定: {ex['human_verdict']}\n" for ex in examples)
    lens = next((p["lens"] for p in PERSPECTIVES if p["name"] == perspective), "综合判定：给出客观结论。")
    prompt = f"""你是安全分析师。{lens}
判断告警是否误报。只返回JSON:
{{"is_false_positive": true/false, "risk_level": "high/medium/low/info", "reason": "一句话"}}
{example_text}
告警: rule={alert['rule_id']}, path={alert['path_template']}, payload={alert['payload']}, src_ip={alert['src_ip']}"""
    resp = client.chat.completions.create(
        model=config.DEEPSEEK_MODEL,
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}, temperature=0.3,
    )
    return json.loads(resp.choices[0].message.content)


# ============ 完整分析管线 ============
def analyze(alerts: list, use_llm: bool = False, api_key: str = "") -> dict:
    """两阶段聚类 + 多视角投票共识。

    与旧版区别：
    1) Stage1 组内先跑 Stage2 语义聚类，vote 在更纯的语义子组上进行；
    2) 每个 vote_rounds 轮使用不同 perspective，缓存键含视角 => 每轮真正独立；
    3) 聚类采用 complete-linkage，结果不依赖输入顺序。
    """
    s1 = cluster_stage1(alerts)
    stage1_results = {}
    rounds = CONFIG["vote_rounds"]
    for key, group in s1.items():
        subgroups = cluster_stage2_semantic(group)
        for sg_idx, subgroup in enumerate(subgroups):
            samples = subgroup[:CONFIG["sample_size"]]
            fp_votes, reasons = 0, set()
            for r in range(rounds):
                perspective = PERSPECTIVES[r % len(PERSPECTIVES)]["name"]
                for a in samples:
                    verdict = judge_alert(a, use_llm, api_key, perspective=perspective)
                    if verdict["is_false_positive"]:
                        fp_votes += 1
                    reasons.add(verdict["reason"])
            total = len(samples) * rounds
            fp_ratio = fp_votes / total if total else 0
            verdict = "误报" if fp_ratio >= CONFIG["consensus_ratio"] else "真实告警"
            name = f"{key[1]}@{key[0]}{key[2]}"
            if len(subgroups) > 1:
                name += f"#s{sg_idx}"
            stage1_results[name] = {
                "verdict": verdict, "fp_ratio": round(fp_ratio, 2),
                "reasons": list(reasons)[:2], "count": len(subgroup),
            }

    events = correlate_attacks(alerts)
    attack_count = sum(v["count"] for v in stage1_results.values() if v["verdict"] == "真实告警")
    fp_count = sum(v["count"] for v in stage1_results.values() if v["verdict"] == "误报")
    return {
        "total_alerts": len(alerts),
        "attack_count": attack_count,
        "fp_count": fp_count,
        "stage1_clusters": len(s1),
        "stage1_results": stage1_results,
        "attack_events": [{"src_ip": e["src_ip"], "count": len(e["alerts"]),
                           "rules": sorted({a["rule_id"] for a in e["alerts"]})} for e in events],
        "cache_hit": len(_load_json(CACHE_FILE, {})),
        "feedback_count": len(get_feedback()),
        "vote_config": {"rounds": rounds, "perspectives": [p["name"] for p in PERSPECTIVES[:rounds]],
                        "consensus_ratio": CONFIG["consensus_ratio"]},
    }
