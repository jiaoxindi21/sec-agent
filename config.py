# -*- coding: utf-8 -*-
"""
统一配置：把散落在各文件里的路径、密钥、阈值集中管理。
所有敏感值优先读环境变量，仓库内只保留开发默认值。
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 数据目录可用环境变量覆盖（容器部署时挂载卷）
DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "secinsight.db")
CACHE_FILE = os.path.join(DATA_DIR, "cache.json")
FEEDBACK_FILE = os.path.join(DATA_DIR, "feedback.json")

# 生产环境必须设置 FLASK_SECRET_KEY，否则 session 可被伪造
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me-in-production")

# LLM 接入参数
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

# 分析内核超参（唯一数据源，core.py 与 app.py 共用）
ANALYSIS = {
    "sample_size": 3,          # 每个聚类组采样条数
    "vote_rounds": 2,          # 投票轮数
    "consensus_ratio": 0.75,   # 误报共识阈值
    "attack_window_minutes": 30,
    "stage2_threshold": 0.35,  # bigram Jaccard 聚合阈值（统一 Web 与内核口径）
}
