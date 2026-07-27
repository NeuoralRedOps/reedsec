"""
DISMA Core — Database Engine
=============================
Scalable storage layer for stealer log records.
Uses SQLite with FTS5 for billions-scale text search.

Architecture:
- WAL mode for concurrent reads/writes
- FTS5 virtual table for instant domain search
- Source-partitioned for logical separation
- Batch insert for bulk imports (10k at a time)
- Streaming generators for large result sets
- Connection pool (thread-local)

Performance targets:
- Single domain lookup: < 10ms (with FTS5 index)
- Bulk insert 1M records: ~2-4 seconds
- Search across 100M+ records: < 50ms
"""

import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator, Optional

from .base_source import StealerLogRecord

logger = logging.getLogger("disma.db")

# Default database path
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "disma_data",
    "stealer_logs.db",
)


class DatabaseEngine:
    """
    Thread-safe database engine with connection pooling via thread-locals.
    
    Schema:
      logs (id, domain, source, record_type, content, url, timestamp, severity, metadata)
      logs_fts (FTS5 virtual table on domain + content)
      sources (name, enabled, last_run, config_hash)
      imports (id, source, file_path, count, started_at, finished_at)
    """

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = DEFAULT_DB_PATH
        self.db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    # ── Connection management ────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=60)
            conn.execute("PRAGMA journal_mode=WAL")        # Concurrent reads
            conn.execute("PRAGMA synchronous=NORMAL")       # Speed vs safety balance
            conn.execute("PRAGMA cache_size=-80000")        # 80MB cache
            conn.execute("PRAGMA busy_timeout=5000")        # 5s busy timeout
            conn.execute("PRAGMA temp_store=MEMORY")        # Temp tables in memory
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def _cursor(self):
        """Get a cursor with automatic commit/rollback."""
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    def close(self):
        """Close all connections (call on shutdown)."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ── Schema initialization ────────────────────────────────────

    def _init_db(self):
        """Create tables and indexes if they don't exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._cursor() as c:
            # Main records table
            c.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain      TEXT NOT NULL,
                    source      TEXT NOT NULL,
                    record_type TEXT NOT NULL DEFAULT 'mention',
                    content     TEXT NOT NULL DEFAULT '',
                    url         TEXT NOT NULL DEFAULT '',
                    timestamp   TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'info',
                    metadata    TEXT NOT NULL DEFAULT '{}',
                    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

            # FTS5 virtual table for lightning-fast domain/content search
            c.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
                    domain, content, url,
                    content=logs,
                    content_rowid=id,
                    tokenize='unicode61 remove_diacritics 2'
                )
            """)

            # Triggers to keep FTS in sync
            for trigger in [
                "CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN "
                "  INSERT INTO logs_fts(rowid, domain, content, url) "
                "  VALUES (new.id, new.domain, new.content, new.url); END;",

                "CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN "
                "  INSERT INTO logs_fts(logs_fts, rowid, domain, content, url) "
                "  VALUES ('delete', old.id, old.domain, old.content, old.url); END;",

                "CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE ON logs BEGIN "
                "  INSERT INTO logs_fts(logs_fts, rowid, domain, content, url) "
                "  VALUES ('delete', old.id, old.domain, old.content, old.url); "
                "  INSERT INTO logs_fts(rowid, domain, content, url) "
                "  VALUES (new.id, new.domain, new.content, new.url); END;",
            ]:
                c.execute(trigger)

            # Sources tracking table
            c.execute("""
                CREATE TABLE IF NOT EXISTS sources (
                    name         TEXT PRIMARY KEY,
                    enabled      INTEGER NOT NULL DEFAULT 1,
                    last_run     TEXT,
                    config_hash  TEXT,
                    total_found  INTEGER NOT NULL DEFAULT 0
                )
            """)

            # Bulk import tracking
            c.execute("""
                CREATE TABLE IF NOT EXISTS imports (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    source      TEXT NOT NULL,
                    file_path   TEXT NOT NULL,
                    count       INTEGER NOT NULL DEFAULT 0,
                    started_at  TEXT NOT NULL,
                    finished_at TEXT
                )
            """)

            # Critical indexes
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON logs(domain)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain_source ON logs(domain, source)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")

            # Optimize FTS
            c.execute("INSERT OR IGNORE INTO logs_fts(logs_fts) VALUES ('optimize')")

            logger.info(f"Database initialized: {self.db_path}")

    # ── Record operations ────────────────────────────────────────

    def insert_record(self, record: StealerLogRecord) -> int:
        """Insert a single record. Returns the row ID."""
        meta_json = json.dumps(record.metadata) if record.metadata else '{}'
        with self._cursor() as c:
            c.execute("""
                INSERT INTO logs (domain, source, record_type, content, url, timestamp, severity, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.domain.lower(),
                record.source,
                record.record_type,
                record.content[:100000],  # Cap content at 100k chars
                record.url,
                record.timestamp,
                record.severity,
                meta_json,
            ))
            row_id = c.lastrowid

            # Update source tracking
            c.execute("""
                INSERT INTO sources (name, total_found) VALUES (?, 1)
                ON CONFLICT(name) DO UPDATE SET
                    total_found = total_found + 1,
                    last_run = datetime('now')
            """, (record.source,))

            return row_id

    def insert_batch(self, records: list[StealerLogRecord]) -> int:
        """
        Bulk insert many records with a single transaction.
        Uses executemany for maximum throughput.
        Returns count of inserted records.
        """
        if not records:
            return 0

        rows = []
        source_counts = {}
        for r in records:
            rows.append((
                r.domain.lower(),
                r.source,
                r.record_type,
                r.content[:100000],
                r.url,
                r.timestamp or datetime.now(timezone.utc).isoformat(),
                r.severity,
                json.dumps(r.metadata) if r.metadata else '{}',
            ))
            source_counts[r.source] = source_counts.get(r.source, 0) + 1

        with self._cursor() as c:
            c.executemany("""
                INSERT INTO logs (domain, source, record_type, content, url, timestamp, severity, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

            for source_name, count in source_counts.items():
                c.execute("""
                    INSERT INTO sources (name, total_found) VALUES (?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        total_found = total_found + ?,
                        last_run = datetime('now')
                """, (source_name, count, count))

        return len(rows)

    # ── Search operations ────────────────────────────────────────

    def search_by_domain(self, domain: str, limit: int = 100, offset: int = 0,
                         source_filter: str = None) -> list[StealerLogRecord]:
        """
        Search for records matching a domain.
        Uses FTS5 for instant lookup even on billions of records.
        """
        domain = domain.lower().strip()

        if source_filter:
            sql = """
                SELECT l.* FROM logs l
                JOIN logs_fts f ON l.rowid = f.rowid
                WHERE logs_fts MATCH ? AND l.source = ?
                ORDER BY l.timestamp DESC
                LIMIT ? OFFSET ?
            """
            params = [self._fts_query(domain), source_filter, limit, offset]
        else:
            sql = """
                SELECT l.* FROM logs l
                JOIN logs_fts f ON l.rowid = f.rowid
                WHERE logs_fts MATCH ?
                ORDER BY l.timestamp DESC
                LIMIT ? OFFSET ?
            """
            params = [self._fts_query(domain), limit, offset]

        return self._execute_and_map(sql, params)

    def search_by_content(self, query: str, limit: int = 50,
                          source_filter: str = None) -> list[StealerLogRecord]:
        """Search across all record content using FTS5."""
        if source_filter:
            sql = """
                SELECT l.* FROM logs l
                JOIN logs_fts f ON l.rowid = f.rowid
                WHERE logs_fts MATCH ? AND l.source = ?
                ORDER BY rank LIMIT ?
            """
            params = [query, source_filter, limit]
        else:
            sql = """
                SELECT l.* FROM logs l
                JOIN logs_fts f ON l.rowid = f.rowid
                WHERE logs_fts MATCH ?
                ORDER BY rank LIMIT ?
            """
            params = [query, limit]

        return self._execute_and_map(sql, params)

    def count_by_domain(self, domain: str, source_filter: str = None) -> dict:
        """Get counts by record_type and severity for a domain."""
        domain = domain.lower().strip()
        result = {"total": 0, "stealer_logs": 0, "credential_leaks": 0, "mentions": 0,
                  "critical": 0, "warning": 0, "info": 0, "sources": {}}

        try:
            with self._cursor() as c:
                if source_filter:
                    c.execute("""
                        SELECT COUNT(*) as cnt FROM logs_fts
                        WHERE logs_fts MATCH ? AND source = ?
                    """, (self._fts_query(domain), source_filter))
                else:
                    c.execute("""
                        SELECT COUNT(*) as cnt FROM logs_fts
                        WHERE logs_fts MATCH ?
                    """, (self._fts_query(domain),))

                row = c.fetchone()
                result["total"] = row["cnt"] if row else 0

                if result["total"] == 0:
                    return result

                # Breakdown by type
                c.execute("""
                    SELECT record_type, COUNT(*) as cnt FROM logs l
                    JOIN logs_fts f ON l.rowid = f.rowid
                    WHERE logs_fts MATCH ?
                    GROUP BY record_type
                """, (self._fts_query(domain),))
                for row in c.fetchall():
                    key = row["record_type"] if row["record_type"] in result else "mentions"
                    result[key] = row["cnt"]

                # Breakdown by severity
                c.execute("""
                    SELECT severity, COUNT(*) as cnt FROM logs l
                    JOIN logs_fts f ON l.rowid = f.rowid
                    WHERE logs_fts MATCH ?
                    GROUP BY severity
                """, (self._fts_query(domain),))
                for row in c.fetchall():
                    sev = row["severity"]
                    if sev in result:
                        result[sev] = row["cnt"]

                # Breakdown by source
                c.execute("""
                    SELECT source, COUNT(*) as cnt FROM logs l
                    JOIN logs_fts f ON l.rowid = f.rowid
                    WHERE logs_fts MATCH ?
                    GROUP BY source
                """, (self._fts_query(domain),))
                for row in c.fetchall():
                    result["sources"][row["source"]] = row["cnt"]

        except Exception as e:
            logger.warning(f"Count query failed for {domain}: {e}")

        return result

    def del_by_domain(self, domain: str) -> int:
        """Delete all records for a domain (used for force-rescan)."""
        domain = domain.lower().strip()
        deleted = 0
        try:
            with self._cursor() as c:
                # Get IDs first to delete from FTS mirror
                c.execute("SELECT id FROM logs WHERE LOWER(domain) = ?", (domain,))
                ids = [r[0] for r in c.fetchall()]
                if not ids:
                    return 0
                # Delete from FTS mirror using 'delete' command
                for rowid in ids:
                    c.execute("INSERT INTO logs_fts(logs_fts, rowid, domain, content, url) VALUES('delete', ?, '', '', '')", (rowid,))
                # Delete from main table
                c.execute("DELETE FROM logs WHERE LOWER(domain) = ?", (domain,))
                deleted = c.rowcount
        except Exception as e:
            logger.warning(f"Delete query failed for {domain}: {e}")
        return deleted

    def stream_all(self, batch_size: int = 1000) -> Generator[list[StealerLogRecord], None, None]:
        """Stream ALL records in batches (for export/backup)."""
        offset = 0
        while True:
            batch = self._execute_and_map(
                "SELECT * FROM logs ORDER BY id LIMIT ? OFFSET ?",
                [batch_size, offset]
            )
            if not batch:
                break
            yield batch
            offset += batch_size

    # ── Internal helpers ─────────────────────────────────────────

    def _fts_query(self, domain: str) -> str:
        """Build an FTS5 query for domain matching."""
        # Escape special chars and use prefix matching
        clean = domain.replace('"', '""')
        return f'"{clean}" OR "{clean}:" OR "*{clean}"'

    def _execute_and_map(self, sql: str, params: list) -> list[StealerLogRecord]:
        """Execute SQL and map results to StealerLogRecord objects."""
        results = []
        try:
            with self._cursor() as c:
                c.execute(sql, params)
                for row in c.fetchall():
                    try:
                        meta = json.loads(row["metadata"]) if row["metadata"] else {}
                    except (json.JSONDecodeError, TypeError):
                        meta = {}
                    results.append(StealerLogRecord(
                        domain=row["domain"],
                        source=row["source"],
                        record_type=row["record_type"],
                        content=row["content"],
                        url=row["url"],
                        timestamp=row["timestamp"],
                        severity=row["severity"],
                        metadata=meta,
                    ))
        except Exception as e:
            logger.warning(f"Query failed: {e}")
        return results

    def get_stats(self) -> dict:
        """Get database statistics."""
        stats = {"total_records": 0, "sources": {}, "db_size_mb": 0}
        try:
            with self._cursor() as c:
                c.execute("SELECT COUNT(*) as cnt FROM logs")
                row = c.fetchone()
                stats["total_records"] = row["cnt"] if row else 0

                c.execute("SELECT name, total_found, last_run FROM sources ORDER BY total_found DESC")
                for row in c.fetchall():
                    stats["sources"][row["name"]] = {
                        "total_found": row["total_found"],
                        "last_run": row["last_run"],
                    }

            if os.path.exists(self.db_path):
                stats["db_size_mb"] = round(os.path.getsize(self.db_path) / (1024 * 1024), 2)

        except Exception as e:
            logger.warning(f"Stats query failed: {e}")

        return stats

    def vacuum(self):
        """Rebuild database to reclaim space (for after bulk deletes)."""
        with self._cursor() as c:
            c.execute("VACUUM")
            c.execute("INSERT INTO logs_fts(logs_fts) VALUES ('rebuild')")
        logger.info("Database vacuum completed")
