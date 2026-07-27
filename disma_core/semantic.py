"""
DISCOPE Semantic Layer
======================
Adds vector-embedding semantic search on top of the existing SQLite+FTS5 store.

Design decisions:
- Local embeddings via sentence-transformers/all-MiniLM-L6-v2 (384-dim, free, offline,
  no OpenAI dependency — Nous API is reserved for chat responses).
- Vectors stored as float32 blobs in SQLite (embeddings table). At MVP scale
  (<100k chunks) brute-force numpy cosine similarity is <200ms — no FAISS/hnsw needed.
- Chunks derived from the existing `logs` table — no duplication of raw content,
  embeddings reference logs.id.
- Thread-safe lazy model load (model load takes ~2s on first call).

Implements PRD §4.2.3 (chunking), FR-2.2/2.3 (embedding generation + storage),
FR-3.2/3.3 (query embedding + top-K retrieval).
"""

import hashlib
import logging
import os
import sqlite3
import struct
import threading
import time
from typing import Optional

import numpy as np

logger = logging.getLogger("discope.semantic")

# ── Config ────────────────────────────────────────────────────────────────────

MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIMS = 384
CHUNK_SIZE = 1000          # chars (approx token proxy: 1 token ≈ 4 chars)
CHUNK_OVERLAP = 200
DEFAULT_TOP_K = 5
BATCH_SIZE = 32

# ── Lazy singleton model ─────────────────────────────────────────────────────

_model = None
_model_lock = threading.Lock()


def _get_model():
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                from sentence_transformers import SentenceTransformer
                logger.info(f"Loading embedding model: {MODEL_NAME}")
                _model = SentenceTransformer(MODEL_NAME)
    return _model


# ── Vector (de)serialization ─────────────────────────────────────────────────

def _vec_to_blob(vec: np.ndarray) -> bytes:
    return vec.astype(np.float32).tobytes()


def _blob_to_vec(blob: bytes) -> np.ndarray:
    return np.frombuffer(blob, dtype=np.float32)


def _cosine_sim_matrix(query: np.ndarray, matrix: np.ndarray) -> np.ndarray:
    """query: (dims,), matrix: (N, dims) → returns (N,) cosine similarities."""
    q = query / (np.linalg.norm(query) + 1e-10)
    m = matrix / (np.linalg.norm(matrix, axis=1, keepdims=True) + 1e-10)
    return m @ q


# ── Chunking ──────────────────────────────────────────────────────────────────

def chunk_text(text: str, chunk_size: int = CHUNK_SIZE,
               overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Recursive character splitter with paragraph/sentence preference.
    Mirrors LangChain RecursiveCharacterTextSplitter behaviour."""
    if not text:
        return []
    chunks = []
    separators = ["\n\n", "\n", ". ", " ", ""]
    _split_recursive(text, chunk_size, overlap, separators, chunks)
    return [c.strip() for c in chunks if c.strip()]


def _split_recursive(text, size, overlap, seps, out):
    if len(text) <= size:
        out.append(text)
        return
    sep = seps[0]
    remaining_seps = seps[1:] if len(seps) > 1 else [""]
    if sep == "":
        # Hard split on char boundary
        for i in range(0, len(text), size - overlap):
            out.append(text[i:i + size])
        return
    parts = text.split(sep)
    current = ""
    for part in parts:
        candidate = current + sep + part if current else part
        if len(candidate) <= size:
            current = candidate
        else:
            if current:
                if len(current) > size:
                    _split_recursive(current, size, overlap, remaining_seps, out)
                else:
                    out.append(current)
            if len(part) > size:
                _split_recursive(part, size, overlap, remaining_seps, out)
                current = ""
            else:
                current = part
    if current:
        if len(current) > size:
            _split_recursive(current, size, overlap, remaining_seps, out)
        else:
            out.append(current)


# ── Store ─────────────────────────────────────────────────────────────────────

class SemanticStore:
    """Embedding storage + retrieval on top of the DISMA SQLite database."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=30)
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def _init_schema(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS embeddings (
                    chunk_id     TEXT PRIMARY KEY,
                    log_id       INTEGER NOT NULL,
                    chunk_index  INTEGER NOT NULL,
                    domain       TEXT NOT NULL,
                    source       TEXT,
                    preview      TEXT,
                    vector       BLOB NOT NULL,
                    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_embeddings_log    ON embeddings(log_id);
                CREATE INDEX IF NOT EXISTS idx_embeddings_domain ON embeddings(domain);

                CREATE TABLE IF NOT EXISTS query_history (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id      TEXT,
                    query_text      TEXT NOT NULL,
                    response_text   TEXT,
                    sources_json    TEXT,
                    response_ms     INTEGER,
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_qh_session ON query_history(session_id);
                CREATE INDEX IF NOT EXISTS idx_qh_created ON query_history(created_at);
            """)
            conn.commit()
        finally:
            conn.close()

    # ── Indexing ──────────────────────────────────────────────────────────

    def index_log(self, log_id: int, domain: str, source: str,
                  content: str) -> int:
        """Chunk + embed a single logs row. Returns number of chunks created.
        Skips if already indexed (idempotent)."""
        conn = self._conn()
        existing = conn.execute(
            "SELECT COUNT(*) FROM embeddings WHERE log_id=?", (log_id,)
        ).fetchone()[0]
        if existing > 0:
            return 0

        chunks = chunk_text(content)
        if not chunks:
            return 0

        model = _get_model()
        rows = []
        for start in range(0, len(chunks), BATCH_SIZE):
            batch = chunks[start:start + BATCH_SIZE]
            vectors = model.encode(batch, convert_to_numpy=True,
                                   show_progress_bar=False)
            for i, (chunk, vec) in enumerate(zip(batch, vectors)):
                chunk_id = hashlib.md5(
                    f"{log_id}:{start+i}:{chunk}".encode()
                ).hexdigest()
                rows.append((
                    chunk_id, log_id, start + i, domain, source,
                    chunk[:200], _vec_to_blob(vec),
                ))
        conn.executemany(
            "INSERT OR IGNORE INTO embeddings "
            "(chunk_id, log_id, chunk_index, domain, source, preview, vector) "
            "VALUES (?,?,?,?,?,?,?)",
            rows,
        )
        conn.commit()
        return len(rows)

    def index_pending(self, limit: int = 500) -> dict:
        """Index any logs rows that don't have embeddings yet.
        Returns {indexed_logs, created_chunks}."""
        conn = self._conn()
        pending = conn.execute("""
            SELECT l.id, l.domain, l.source, l.content FROM logs l
            LEFT JOIN embeddings e ON e.log_id = l.id
            WHERE e.log_id IS NULL AND length(l.content) > 20
            LIMIT ?
        """, (limit,)).fetchall()

        indexed, chunks_created = 0, 0
        for log_id, domain, source, content in pending:
            try:
                n = self.index_log(log_id, domain, source, content)
                if n:
                    indexed += 1
                    chunks_created += n
            except Exception as e:
                logger.warning(f"index_log failed for {log_id}: {e}")
        return {"indexed_logs": indexed, "created_chunks": chunks_created}

    # ── Retrieval ─────────────────────────────────────────────────────────

    def query(self, question: str, top_k: int = DEFAULT_TOP_K,
              domain_filter: Optional[str] = None) -> list[dict]:
        """Semantic similarity search. Returns list of
        {chunk_id, log_id, domain, source, preview, score}."""
        conn = self._conn()
        if domain_filter:
            rows = conn.execute(
                "SELECT chunk_id, log_id, domain, source, preview, vector "
                "FROM embeddings WHERE domain = ?",
                (domain_filter,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT chunk_id, log_id, domain, source, preview, vector "
                "FROM embeddings"
            ).fetchall()

        if not rows:
            return []

        model = _get_model()
        q_vec = model.encode([question], convert_to_numpy=True,
                             show_progress_bar=False)[0]

        matrix = np.stack([_blob_to_vec(r[5]) for r in rows])
        scores = _cosine_sim_matrix(q_vec, matrix)

        top_idx = np.argsort(scores)[::-1][:top_k]
        results = []
        for i in top_idx:
            r = rows[i]
            results.append({
                "chunk_id": r[0],
                "log_id": r[1],
                "domain": r[2],
                "source": r[3],
                "preview": r[4],
                "score": float(scores[i]),
            })
        return results

    # ── History ───────────────────────────────────────────────────────────

    def log_query(self, session_id: str, query: str, response: str,
                  sources: list, response_ms: int):
        import json as _json
        conn = self._conn()
        conn.execute(
            "INSERT INTO query_history "
            "(session_id, query_text, response_text, sources_json, response_ms) "
            "VALUES (?,?,?,?,?)",
            (session_id, query, response, _json.dumps(sources), response_ms),
        )
        conn.commit()

    def get_history(self, session_id: Optional[str] = None,
                    limit: int = 50) -> list[dict]:
        conn = self._conn()
        if session_id:
            rows = conn.execute(
                "SELECT id, session_id, query_text, response_text, "
                "sources_json, response_ms, created_at FROM query_history "
                "WHERE session_id=? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, session_id, query_text, response_text, "
                "sources_json, response_ms, created_at FROM query_history "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r[0], "session_id": r[1], "query": r[2],
                "response": r[3], "sources": r[4], "response_ms": r[5],
                "created_at": r[6],
            }
            for r in rows
        ]

    def stats(self) -> dict:
        conn = self._conn()
        chunks = conn.execute("SELECT COUNT(*) FROM embeddings").fetchone()[0]
        logs_indexed = conn.execute(
            "SELECT COUNT(DISTINCT log_id) FROM embeddings"
        ).fetchone()[0]
        domains = conn.execute(
            "SELECT COUNT(DISTINCT domain) FROM embeddings"
        ).fetchone()[0]
        queries = conn.execute("SELECT COUNT(*) FROM query_history").fetchone()[0]
        return {
            "total_chunks": chunks,
            "indexed_logs": logs_indexed,
            "domains": domains,
            "queries_logged": queries,
            "embedding_model": MODEL_NAME,
            "embedding_dims": EMBEDDING_DIMS,
        }
