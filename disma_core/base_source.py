"""
DISMA Core — Base Data Source Plugin
=====================================
Abstract base class for all stealer log data sources.
Drop a new plugin in disma_core/sources/ and register it in config.yaml.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import logging

logger = logging.getLogger("disma.source")


@dataclass
class StealerLogRecord:
    """A single record found by a data source."""
    domain: str
    source: str                # Source plugin name (e.g. "pastebin", "telegram")
    record_type: str           # "stealer_log", "credential_leak", "mention"
    content: str               # The raw content / snippet
    url: str = ""              # Where it was found
    timestamp: str = ""        # When it was found/discovered
    severity: str = "info"     # "critical", "warning", "info"
    metadata: dict = field(default_factory=dict)  # Extra source-specific data

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class DataSource(ABC):
    """
    Abstract base class for a data source plugin.
    
    To add a new source:
    1. Create a new file in disma_core/sources/my_source.py
    2. Subclass DataSource
    3. Implement fetch() and configure()
    4. Add config to disma_config.yaml
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.name = self.__class__.__name__.lower()
        self._base_name = self.name
        self.enabled = self.config.get("enabled", True)

    @abstractmethod
    def configure(self, config: dict):
        """Configure this source from the YAML config dict."""
        pass

    @abstractmethod
    def fetch(self, domain: str, limit: int = 100) -> list[StealerLogRecord]:
        """
        Search this source for records matching the domain.
        Returns a list of StealerLogRecord objects.
        Must handle errors gracefully — never raise, always return [].
        """
        pass

    def bulk_import(self, file_path: str) -> int:
        """
        Optional: Bulk import records from a file (for large datasets/dumps).
        Returns number of records imported.
        """
        return 0

    def validate_config(self) -> bool:
        """Override to validate required config fields."""
        return True

    def status(self) -> dict:
        """Return status info for this source."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "configured": self.validate_config(),
        }


class Registry:
    """
    Plugin registry — auto-discovers and manages data source plugins.
    """

    def __init__(self):
        self._sources: dict[str, DataSource] = {}

    def register(self, source: DataSource):
        """Register a single source instance."""
        self._sources[source.name] = source
        logger.info(f"Registered source: {source.name} (enabled={source.enabled})")

    def get(self, name: str) -> Optional[DataSource]:
        return self._sources.get(name)

    def get_enabled(self) -> list[DataSource]:
        return [s for s in self._sources.values() if s.enabled]

    def all(self) -> list[DataSource]:
        return list(self._sources.values())

    def __len__(self):
        return len(self._sources)

    def status_all(self) -> dict:
        return {name: src.status() for name, src in self._sources.items()}
