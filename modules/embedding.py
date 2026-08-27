"""M3 embedding — 高效向量检索。

本地实现（默认，零依赖）：分词 → 哈希桶计数向量 → L2 归一化 → 余弦相似度。
可选切换：config.embedding.provider = "openai" 时调用 OpenAI 兼容 embeddings API，
失败自动回退本地。

能力：
  provider()           当前生效 provider
  embed(text)          单文本向量
  remember(text, meta) 加入内存索引（经验回流用）
  search(query, top_k) 检索最相似条目
  save_index()/load_index()  索引持久化
"""
import json
import math
import os
import re
import threading
import time
import urllib.error
import urllib.request

from core import config, logger

INDEX_FILE = os.path.join(config.ROOT, "embedding_index.json")

TOKEN_RE = re.compile(r"[A-Za-z0-9_]+|[\u4e00-\u9fff]", re.U)
CJK_RE = re.compile(r"[\u4e00-\u9fff]")
STOP = set("the a an of and or to in on for with is are was be by at as it this "
           "that from i you we they he she them they it's not no yes ok".split())


def _tokens(text):
    if not text:
        return []
    text = text.lower()
    out = []
    for t in TOKEN_RE.findall(text):
        if len(t) < 2 and not CJK_RE.match(t):
            continue
        if t in STOP:
            continue
        out.append(t)
    return out


def _hash_token(tok, dim):
    h = 2166136261
    for ch in tok.encode("utf-8"):
        h = ((h ^ ch) * 16777619) & 0xFFFFFFFF
    return h % dim


def cosine(a, b):
    return sum(x * y for x, y in zip(a, b))


def _local_vec(text, dim):
    vec = [0.0] * dim
    for tok in _tokens(text):
        vec[_hash_token(tok, dim)] += 1.0
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


class BaseIndex:
    """共享的文档存取/检索骨架，向量生成由子类提供。"""

    def __init__(self, dim=256):
        self.dim = dim
        self.docs = []

    def embed(self, text):  # pragma: no cover - 子类必须实现
        raise NotImplementedError

    def add(self, text, meta=None):
        vec = self.embed(text)
        if vec is None:
            return None
        self.docs.append({"text": text, "vec": vec, "meta": meta or {}})
        return len(self.docs) - 1

    def search(self, query, top_k=5, min_score=0.0):
        qv = self.embed(query)
        if qv is None:
            return None
        scored = []
        for i, doc in enumerate(self.docs):
            s = cosine(qv, doc["vec"])
            if s >= min_score:
                scored.append({"idx": i, "score": round(s, 4),
                               "text": doc["text"], "meta": doc["meta"]})
        scored.sort(key=lambda x: -x["score"])
        return scored[:top_k]

    def size(self):
        return len(self.docs)

    def dump(self):
        return {"dim": self.dim,
                "docs": [{"text": d["text"], "meta": d["meta"]} for d in self.docs]}

    def _load_docs(self, data, embed_fn):
        try:
            self.dim = max(1, int(data.get("dim", self.dim) or self.dim))
        except (TypeError, ValueError):
            self.dim = max(1, self.dim)
        self.docs = []
        for d in (data.get("docs") or []):
            if not isinstance(d, dict):
                continue
            text = d.get("text")
            if not isinstance(text, str):
                continue  # 非字符串文本跳过，避免 _tokens(text).lower() 崩溃致半载状态
            meta = d.get("meta")
            if not isinstance(meta, dict):
                meta = {}
            vec = embed_fn(text)
            if vec is not None:
                self.docs.append({"text": text, "vec": vec, "meta": meta})


class LocalIndex(BaseIndex):
    def embed(self, text):
        return _local_vec(text, self.dim)

    def load(self, data):
        self._load_docs(data, lambda t: _local_vec(t, self.dim))


class OpenAIEmbed(BaseIndex):
    def _call(self, texts):
        sec = config.section("ai")
        base = (sec.get("base_url") or "").rstrip("/")
        key = sec.get("api_key") or os.environ.get(
            sec.get("api_key_env") or "RETRACE_API_KEY", "")
        model = sec.get("embedding_model") or config.section("embedding").get(
            "openai_model") or ""
        if not base or not key:
            return None
        url = base + "/embeddings"
        body = json.dumps({"model": model, "input": texts}).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + key)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as e:
            logger.warn("embedding API 调用失败，回退本地: %s" % e)
            return None
        items = data.get("data", [])
        if not items:
            return None
        return [it.get("embedding") or [] for it in items]

    def embed(self, text):
        vecs = self._call([text])
        if not vecs:
            return None
        vec = vecs[0]
        return vec[:self.dim] or None

    def load(self, data):
        # 载入即重新向量化：API 维度可能与本地不同，且离线时跳过坏条目
        self._load_docs(data, self.embed)


_index = None
_index_lock = threading.RLock()


def provider():
    sec = config.section("embedding")
    return sec.get("provider", "local")


def get_index():
    global _index
    with _index_lock:
        if _index is None:
            if provider() == "openai":
                _index = OpenAIEmbed()
            else:
                _index = LocalIndex()
            _load()
        return _index


def embed(text):
    idx = get_index()
    if isinstance(idx, OpenAIEmbed):
        vec = idx.embed(text)
        return vec if vec is not None else _local_vec(text, 256)
    return idx.embed(text)


def remember(text, meta=None):
    try:
        from core import db
        db.audit("embedding.remember", "len=%d" % len(text or ""))
    except Exception:
        pass
    idx = get_index()
    meta = dict(meta or {})
    meta.setdefault("at", time.strftime("%Y-%m-%d %H:%M:%S"))
    return idx.add(text, meta)


def search(query, top_k=5, min_score=0.0):
    idx = get_index()
    if isinstance(idx, OpenAIEmbed):
        res = idx.search(query, top_k, min_score)
        if res is None:
            # API 失效：用本地哈希向量兜底重建临时索引检索
            idx_local = LocalIndex(dim=idx.dim)
            for d in idx.docs:
                idx_local.add(d["text"], d["meta"])
            return idx_local.search(query, top_k, min_score) or []
        return res
    return idx.search(query, top_k, min_score) or []


def save_index():
    with _index_lock:
        if _index is None:
            return False
        try:
            with open(INDEX_FILE, "w", encoding="utf-8") as f:
                json.dump(_index.dump(), f, ensure_ascii=False)
            return True
        except OSError as e:
            logger.record_err("embedding.save", e)
            return False


def _load():
    with _index_lock:
        if _index is None:
            return False
        if not os.path.exists(INDEX_FILE):
            return False  # 首次运行无索引属正常，不算错误
        try:
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.warn("embedding 索引文件格式非法（非对象），已忽略")
                return False
            _index.load(data)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            logger.record_err("embedding.load", e)
            return False
        return True


def stats():
    idx = get_index()
    return {"provider": provider(), "docs": idx.size(), "dim": idx.dim}


def register(bus, cfg):
    bus.subscribe("embedding.remember",
                  lambda d: remember(d.get("text", ""), d.get("meta"))
                  if d and d.get("text") else None)


def shutdown():
    save_index()
