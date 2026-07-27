"""
DISMA Core — Engine
===================
The orchestrator that ties together:
- Data source plugins (Telegram, API, paste sites, etc.)
- Database engine (SQLite + FTS5)
- Configuration management
- Search/query operations

This is the single entry point for the web server.
"""

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from .base_source import DataSource, Registry, StealerLogRecord
from .database import DatabaseEngine

logger = logging.getLogger("disma.engine")


class DISMAEngine:
    """
    Main engine that manages sources, storage, and queries.
    
    Usage:
        engine = DISMAEngine()
        engine.auto_discover_sources()
        results = engine.scan_domain("example.com")
    """

    def __init__(self, db_path: str = None, config_path: str = None):
        self.db = DatabaseEngine(db_path)
        self.registry = Registry()
        self.config = {}
        self._executor = ThreadPoolExecutor(max_workers=4)

        if config_path:
            self.load_config(config_path)

    # ── Configuration ────────────────────────────────────────────

    def load_config(self, config_path: str):
        """Load configuration from a YAML file."""
        import yaml  # Optional dependency
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        logger.info(f"Loaded config from {config_path}")

    def get_source_config(self, source_name: str) -> dict:
        """Get configuration for a specific source from config."""
        sources_cfg = self.config.get("sources", {})
        return sources_cfg.get(source_name, {})

    # ── Source management ────────────────────────────────────────

    def register_source(self, source: DataSource):
        """Register a single data source plugin."""
        # Apply config if available
        src_config = self.get_source_config(source.name)
        if src_config:
            source.configure(src_config)
        self.registry.register(source)

    def auto_discover_sources(self):
        """
        Automatically discover and register all source plugins
        from the disma_core/sources/ directory.
        """
        import importlib
        import pkgutil
        import sys

        package = "disma_core.sources"
        
        # Ensure the package path is in sys.path
        scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        try:
            import disma_core.sources as src_pkg
            for importer, modname, ispkg in pkgutil.iter_modules(src_pkg.__path__):
                if modname.startswith("_") or ispkg:
                    continue
                try:
                    module = importlib.import_module(f"{package}.{modname}")
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and
                                issubclass(attr, DataSource) and
                                attr is not DataSource):
                            instance = attr()
                            self.register_source(instance)
                            logger.info(f"Discovered source: {instance.name}")
                except Exception as e:
                    logger.warning(f"Failed to load source module {modname}: {e}")
        except ImportError as e:
            logger.warning(f"No sources package found: {e}")

    # ── Scanning operations ──────────────────────────────────────

    def scan_domain(self, domain: str, timeout: int = 180, bypass_cache: bool = False) -> dict:
        """
        Scan a domain across ALL enabled sources.
        Runs sources in parallel, aggregates results.
        
        Returns:
        {
            "domain": "example.com",
            "total_found": 0,
            "stealer_logs": 0,
            "credential_leaks": 0,
            "mentions": 0,
            "critical": 0,
            "warning": 0,
            "clean": true/false,
            "sources_checked": [...],
            "records": [...],
            "scan_time_ms": 123,
        }
        """
        domain = domain.lower().strip()
        start = time.time()

        result = {
            "domain": domain,
            "total_found": 0,
            "stealer_logs": 0,
            "credential_leaks": 0,
            "mentions": 0,
            "critical": 0,
            "warning": 0,
            "info": 0,
            "clean": True,
            "sources_checked": [],
            "records": [],
            "scan_time_ms": 0,
        }

        # First, check the database cache (skip if bypass_cache=True for force-rescan)
        if bypass_cache:
            cached = {"total": 0}
            # Optionally clear existing records for this domain before live scan
            try:
                self.db.del_by_domain(domain)
            except AttributeError:
                pass
            except Exception:
                pass
        else:
            cached = self.db.count_by_domain(domain)
        if cached["total"] > 0:
            # We already have data — search the DB
            records = self.db.search_by_domain(domain, limit=200)
            db_records = self.db.count_by_domain(domain)
            result["total_found"] = db_records["total"]
            result["stealer_logs"] = db_records["stealer_logs"]
            result["credential_leaks"] = db_records["credential_leaks"]
            result["mentions"] = db_records["mentions"]
            result["critical"] = db_records["critical"]
            result["warning"] = db_records["warning"]
            result["records"] = [self._record_to_dict(r) for r in records]
            result["clean"] = result["total_found"] == 0 or (
                result["critical"] == 0 and result["warning"] == 0
            )
            result["sources_checked"] = list(db_records.get("sources", {}).keys())
            result["scan_time_ms"] = round((time.time() - start) * 1000)
            result["from_cache"] = True
            return result

        # Cache miss — scan live sources
        enabled = self.registry.get_enabled()
        if not enabled:
            result["scan_time_ms"] = round((time.time() - start) * 1000)
            result["note"] = "No enabled data sources configured"
            return result

        all_records = []
        futures = {}

        for source in enabled:
            futures[self._executor.submit(self._safe_fetch, source, domain)] = source.name

        for future in as_completed(futures, timeout=timeout):
            source_name = futures[future]
            result["sources_checked"].append(source_name)
            try:
                records = future.result(timeout=10)
                all_records.extend(records)
            except Exception as e:
                logger.warning(f"Source {source_name} failed: {e}")

        # Store results in database
        if all_records:
            self.db.insert_batch(all_records)

        # Aggregate counts
        for rec in all_records:
            result["total_found"] += 1
            if rec.record_type == "stealer_log":
                result["stealer_logs"] += 1
            elif rec.record_type == "credential_leak":
                result["credential_leaks"] += 1
            else:
                result["mentions"] += 1

            if rec.severity == "critical":
                result["critical"] += 1
            elif rec.severity == "warning":
                result["warning"] += 1
            else:
                result["info"] += 1

        result["clean"] = (result["critical"] == 0 and result["warning"] == 0)
        result["records"] = [self._record_to_dict(r) for r in all_records[:200]]
        result["scan_time_ms"] = round((time.time() - start) * 1000)

        return result

    def _safe_fetch(self, source: DataSource, domain: str) -> list[StealerLogRecord]:
        """Safely fetch from a source with error handling."""
        try:
            return source.fetch(domain, limit=500)
        except Exception as e:
            logger.error(f"Error in source {source.name}: {e}")
            return []

    # ── Bulk import ──────────────────────────────────────────────

    def bulk_import(self, file_path: str, source_name: str = "bulk_import") -> dict:
        """
        Bulk import records from a file (JSONL, CSV, or plain text).
        
        File formats supported:
        - JSONL: One JSON object per line with domain/content/type fields
        - CSV: domain,content,type,severity header
        - TXT: One record per line, domain extracted automatically
        
        Returns import stats.
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        ext = os.path.splitext(file_path)[1].lower()
        start = time.time()
        imported = 0
        batch = []

        try:
            if ext == ".jsonl":
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            record = self._dict_to_record(data, source_name)
                            batch.append(record)
                            if len(batch) >= 10000:
                                imported += self.db.insert_batch(batch)
                                batch = []
                        except (json.JSONDecodeError, Exception):
                            continue

            elif ext == ".csv":
                import csv
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        record = self._dict_to_record(row, source_name)
                        batch.append(record)
                        if len(batch) >= 10000:
                            imported += self.db.insert_batch(batch)
                            batch = []

            else:  # Plain text — one entry per line
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line or len(line) < 4:
                            continue
                        record = StealerLogRecord(
                            domain=self._extract_domain(line) or "unknown",
                            source=source_name,
                            record_type="mention",
                            content=line[:10000],
                            severity="info",
                        )
                        batch.append(record)
                        if len(batch) >= 10000:
                            imported += self.db.insert_batch(batch)
                            batch = []

            # Flush remaining
            if batch:
                imported += self.db.insert_batch(batch)

        except Exception as e:
            logger.error(f"Bulk import failed: {e}")
            return {"error": str(e), "imported": imported, "file": file_path}

        elapsed = round(time.time() - start, 2)
        logger.info(f"Bulk import: {imported} records from {file_path} in {elapsed}s")

        return {
            "imported": imported,
            "source": source_name,
            "file": file_path,
            "elapsed_seconds": elapsed,
            "records_per_second": round(imported / elapsed, 1) if elapsed > 0 else 0,
        }

    # ── Query helpers ────────────────────────────────────────────

    def query(self, domain: str, limit: int = 50) -> dict:
        """Quick domain query — checks database only, no live scan."""
        records = self.db.search_by_domain(domain, limit=limit)
        counts = self.db.count_by_domain(domain)
        return {
            "domain": domain,
            "total_found": counts["total"],
            "records": [self._record_to_dict(r) for r in records],
            "counts": counts,
        }

    def stats(self) -> dict:
        """Get overall engine and database stats."""
        db_stats = self.db.get_stats()
        return {
            "database": db_stats,
            "sources": self.registry.status_all(),
            "version": "2.0.0",
        }

    # ── Internal helpers ─────────────────────────────────────────

    def _record_to_dict(self, rec: StealerLogRecord) -> dict:
        return {
            "domain": rec.domain,
            "source": rec.source,
            "type": rec.record_type,
            "content": rec.content[:500],  # Truncate for API response
            "url": rec.url,
            "timestamp": rec.timestamp,
            "severity": rec.severity,
            "metadata": rec.metadata,
        }

    def _dict_to_record(self, data: dict, default_source: str) -> StealerLogRecord:
        return StealerLogRecord(
            domain=str(data.get("domain", data.get("Domain", "unknown"))),
            source=str(data.get("source", data.get("Source", default_source))),
            record_type=str(data.get("type", data.get("Type", "mention"))),
            content=str(data.get("content", data.get("Content", ""))),
            url=str(data.get("url", data.get("Url", ""))),
            severity=str(data.get("severity", data.get("Severity", "info"))),
        )

    @staticmethod
    def _extract_domain(text: str) -> Optional[str]:
        """Extract a domain from arbitrary text."""
        import re
        m = re.search(r'([\w.-]+\.[\w]{2,})', text)
        return m.group(1).lower() if m else None

    def shutdown(self):
        """Clean shutdown."""
        self._executor.shutdown(wait=True)
        self.db.close()
        logger.info("DISMA Engine shutdown complete")
