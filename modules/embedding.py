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
import urllib.error
import urllib.request

from core import config, logger

INDEX_FILE = os.path.join(config.ROOT, "embedding_index.json")

TOKEN_RE = re.compile(r"[A-Za-z0-9_]+|[\u4e00-\u9fff]", re.U)
STOP = set("the a an of and or to in on for with is are was be by at as it this "
           "that from i you we they he she them they it's not no yes ok".split())


def _tokens(text):
    if not text:
        return []
    text = text.lower()
    out = []
    for t in TOKEN_RE.findall(text):
        if len(t) < 2 and not re.match(r"[\u4e00-\u9fff]", t):
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


class LocalIndex:
    def __init__(self, dim=256):
        self.dim = dim
        self.docs = []

    def embed(self, text):
        vec = [0.0] * self.dim
        for tok in _tokens(text):
            vec[_hash_token(tok, self.dim)] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec

    def add(self, text, meta=None):
        vec = self.embed(text)
        self.docs.append({"text": text, "vec": vec, "meta": meta or {}})
        return len(self.docs) - 1

    def _cosine(self, a, b):
        s = 0.0
        for x, y in zip(a, b):
            s += x * y
        return s

    def search(self, query, top_k=5, min_score=0.0):
        qv = self.embed(query)
        scored = []
        for i, doc in enumerate(self.docs):
            s = self._cosine(qv, doc["vec"])
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

    def load(self, data):
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
            self.docs.append({"text": text, "vec": self.embed(text), "meta": meta})


class OpenAIEmbed:
    def __init__(self, dim=256):
        self.dim = dim
        self.docs = []

    def _call(self, texts):
        sec = config.section("ai")
        base = (sec.get("base_url") or "").rstrip("/")
        key = sec.get("api_key") or os.environ.get(sec.get("api_key_env") or "",
                                                   "")
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

    def add(self, text, meta=None):
        vec = self.embed(text)
        if vec is None:
            return None
        self.docs.append({"text": text, "vec": vec, "meta": meta or {}})
        return len(self.docs) - 1

    def _cosine(self, a, b):
        s = 0.0
        for x, y in zip(a, b):
            s += x * y
        return s

    def search(self, query, top_k=5, min_score=0.0):
        qv = self.embed(query)
        if qv is None:
            return None
        scored = []
        for i, doc in enumerate(self.docs):
            s = self._cosine(qv, doc["vec"])
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

    def load(self, data):
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
            vec = self.embed(text)
            if vec is not None:
                self.docs.append({"text": text, "vec": vec, "meta": meta})


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
        return vec if vec is not None else LocalIndex().embed(text)
    return idx.embed(text)


def remember(text, meta=None):
    try:
        from core import db
        db.audit("embedding.remember", "len=%d" % len(text or ""))
    except Exception:
        pass
    idx = get_index()
    meta = dict(meta or {})
    meta.setdefault("at", __import__("time").strftime("%Y-%m-%d %H:%M:%S"))
    i = None
    if isinstance(idx, OpenAIEmbed):
        i = idx.add(text, meta)
        if i is None:
            return None
    else:
        i = idx.add(text, meta)
    return i


def search(query, top_k=5, min_score=0.0):
    idx = get_index()
    if isinstance(idx, OpenAIEmbed):
        res = idx.search(query, top_k, min_score)
        if res is None:
            idx_local = LocalIndex()
            for d in idx.docs:
                idx_local.add(d["text"], d["meta"])
            return idx_local.search(query, top_k, min_score)
        return sorted(res, key=lambda x: -x["score"])[:top_k]
    return idx.search(query, top_k, min_score)


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