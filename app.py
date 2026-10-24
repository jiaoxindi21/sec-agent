# -*- coding: utf-8 -*-
"""
sec-agent —— 告警自动研判 Agent（独立于 sec-analyzer 的 Agent 项目）
运行在 8081 端口：python app.py
"""
import json
import os
import sys

from flask import Flask, jsonify, render_template, request

# 复用 sec-analyzer 的分析内核
sys.path.insert(0, os.path.dirname(__file__))

# 从 .env 加载 DeepSeek key（若未设置环境变量）
_env_file = os.path.join(os.path.dirname(__file__), ".env")
if not os.environ.get("DEEPSEEK_API_KEY") and os.path.exists(_env_file):
    with open(_env_file, "r", encoding="utf-8") as _f:
        for _line in _f:
            if "=" in _line and not _line.strip().startswith("#"):
                _k, _v = _line.strip().split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

from agent import Agent
import tools

app = Flask(__name__)
app.secret_key = "sec-agent-secret"

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _merge_uploads(filepaths: list) -> str:
    """把多个 JSON/JSONL 文件的记录合并成一个临时文件，返回其路径"""
    all_records = []
    for fp in filepaths:
        if os.path.exists(fp):
            all_records.extend(tools._load_records(fp))
    merged_path = os.path.join(UPLOAD_DIR, f"_merged_{int(__import__('time').time())}.json")
    with open(merged_path, "w", encoding="utf-8") as f:
        for rec in all_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return merged_path


@app.route("/")
def index():
    return render_template("agent.html", active="agent")


@app.route("/api/agent/upload", methods=["POST"])
def agent_upload():
    """接收一个或多个告警 JSON 文件，保存到 uploads/，返回路径列表"""
    files = request.files.getlist("file")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "未收到文件"}), 400
    saved = []
    for f in files:
        if not f.filename.lower().endswith(".json"):
            continue
        fname = f"{int(__import__('time').time())}_{f.filename}"
        path = os.path.join(UPLOAD_DIR, fname)
        f.save(path)
        saved.append({"filename": f.filename, "filepath": path})
    if not saved:
        return jsonify({"error": "仅支持 JSON 文件"}), 400
    return jsonify({"ok": True, "files": saved})


@app.route("/api/agent/run", methods=["POST"])
def agent_run():
    task = request.json.get("task", "").strip()
    filepaths = request.json.get("filepaths") or []
    if not task:
        return jsonify({"error": "任务不能为空"}), 400
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")

    # 多文件合并：把上传的多个 JSON/JSONL 记录合并成一个临时文件后统一分析
    merged = _merge_uploads(filepaths) if filepaths else ""

    agent = Agent(api_key=api_key)
    result = agent.run(task, merged)
    # 若生成了报告文件，把内容一起返回，前端直接展示
    if result.get("final", {}).get("kind") == "report":
        rp = result["final"]["data"].get("report_path")
        if rp and os.path.exists(rp):
            with open(rp, "r", encoding="utf-8") as f:
                result["final"]["report_html"] = f.read()
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)
