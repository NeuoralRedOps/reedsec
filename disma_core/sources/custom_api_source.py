"""
DISMA Source — Custom API Source
=================================
A template/plugin for adding ANY custom API source.
Use this when you find a new API that provides stealer log data.

HOW TO ADD A NEW SOURCE:
1. Copy this file or add config in disma_config.yaml
2. Set the API endpoint, key, and field mappings
3. Enable it in config — done!

Example config:
  sources:
    my_leak_api:
      type: api
      enabled: true
      name: "My Leak Database"
      endpoint: "https://api.example.com/search"
      api_key: "your-api-key-here"
      method: "POST"
      field_mapping:
        domain: "domain"
        content: "raw_data"
        type: "record_type"
        severity: "threat_level"
        url: "source_url"
"""

import json
import logging
import subprocess
from urllib.parse import urlencode

from disma_core.base_source import DataSource, StealerLogRecord

logger = logging.getLogger("disma.source.custom_api")


class CustomAPISource(DataSource):
    """
    Generic API source — configure via YAML to connect to any API.
    Supports GET and POST, custom headers, response field mapping.
    """

    def __init__(self, config: dict = None):
        # Call parent but handle name property override
        DataSource.__init__(self, config)
        # Allow instance naming so multiple custom APIs can coexist
        self._instance_name = None
        self.api_endpoint = ""
        self.api_key = ""
        self.api_header = "Authorization"
        self.api_header_format = "Bearer {}"
        self.method = "GET"
        self.response_path = "data"
        self.timeout = 30
        self.max_results = 500
        self.field_mapping = {
            "domain": "domain",
            "content": "content",
            "type": "type",
            "severity": "severity",
            "url": "url",
            "timestamp": "timestamp",
        }
        self.custom_name = ""
        if config:
            self.configure(config)

    @property
    def name(self) -> str:
        return self._instance_name or self._base_name

    @name.setter
    def name(self, value: str):
        self._instance_name = value

    def configure(self, config: dict):
        """Configure from YAML config dict."""
        self.api_endpoint = config.get("endpoint", self.api_endpoint)
        self.api_key = config.get("api_key", self.api_key)
        self.api_header = config.get("api_header", self.api_header)
        self.api_header_format = config.get("api_header_format", self.api_header_format)
        self.method = config.get("method", self.method)
        self.response_path = config.get("response_path", self.response_path)
        self.timeout = config.get("timeout", self.timeout)
        self.max_results = config.get("max_results", self.max_results)
        field_map = config.get("field_mapping")
        if field_map:
            self.field_mapping.update(field_map)
        self.custom_name = config.get("name", self.custom_name)
        self.enabled = config.get("enabled", self.enabled)
        if self.custom_name:
            self._instance_name = self.custom_name.lower().replace(" ", "_")

    def validate_config(self) -> bool:
        if not self.api_endpoint:
            logger.warning(f"CustomAPISource '{self.name}' has no endpoint configured")
            return False
        return True

    def fetch(self, domain: str, limit: int = 100) -> list[StealerLogRecord]:
        """Search the custom API for domain mentions."""
        records = []
        if not self.validate_config():
            return records

        limit = min(limit, self.max_results)
        domain_clean = domain.lower().strip()

        try:
            headers = ["-H", "Content-Type: application/json"]
            if self.api_key:
                auth_value = self.api_header_format.replace("{}", self.api_key)
                headers.extend(["-H", f"{self.api_header}: {auth_value}"])

            if self.method.upper() == "POST":
                # POST request with domain in body
                payload = json.dumps({"domain": domain_clean, "limit": limit})
                cmd = [
                    "curl", "-sk", "--max-time", str(self.timeout),
                    "-X", "POST", self.api_endpoint,
                ] + headers + ["-d", payload]
            else:
                # GET request with domain as query param
                params = urlencode({"domain": domain_clean, "limit": limit})
                full_url = f"{self.api_endpoint}?{params}"
                cmd = [
                    "curl", "-sk", "--max-time", str(self.timeout),
                ] + headers + [full_url]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout + 5,
            )

            if result.stdout:
                data = json.loads(result.stdout)

                # Navigate response path
                items = self._navigate_path(data, self.response_path)
                if not isinstance(items, list):
                    items = [items] if items else []

                for item in items[:limit]:
                    if isinstance(item, dict):
                        record = self._map_response(item, domain_clean)
                        if record:
                            records.append(record)

        except subprocess.TimeoutExpired:
            logger.warning(f"Custom API '{self.name}' timed out for {domain}")
        except json.JSONDecodeError:
            logger.warning(f"Custom API '{self.name}' returned non-JSON for {domain}")
        except Exception as e:
            logger.warning(f"Custom API '{self.name}' error for {domain}: {e}")

        return records

    def _map_response(self, item: dict, domain: str) -> StealerLogRecord:
        """Map API response fields to StealerLogRecord using configured mapping."""
        try:
            return StealerLogRecord(
                domain=str(item.get(self.field_mapping.get("domain", "domain"), domain)),
                source=self.name,
                record_type=str(item.get(self.field_mapping.get("type", "type"), "mention")),
                content=str(item.get(self.field_mapping.get("content", "content"), "")),
                url=str(item.get(self.field_mapping.get("url", "url"), "")),
                timestamp=str(item.get(self.field_mapping.get("timestamp", "timestamp"), "")),
                severity=str(item.get(self.field_mapping.get("severity", "severity"), "info")),
                metadata={"source": self.name, "raw_fields": list(item.keys())},
            )
        except Exception as e:
            logger.warning(f"Failed to map response item: {e}")
            return None

    def bulk_import(self, file_path: str) -> int:
        """
        Bulk import from a JSONL file.
        Each line should be a JSON object matching the field mapping.
        """
        import json
        count = 0
        batch = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        record = self._map_response(item, item.get("domain", "unknown"))
                        if record:
                            batch.append(record)
                            count += 1
                        if len(batch) >= 10000:
                            self._flush_batch(batch)
                            batch = []
                    except json.JSONDecodeError:
                        continue

            if batch:
                self._flush_batch(batch)

        except Exception as e:
            logger.error(f"Bulk import failed for {self.name}: {e}")

        return count

    def _flush_batch(self, records: list):
        """Store batch via database (called from bulk_import)."""
        from disma_core.database import DatabaseEngine
        db = DatabaseEngine()
        db.insert_batch(records)

    @staticmethod
    def _navigate_path(data, path: str):
        """Navigate a dotted path in a nested dict (e.g. 'response.data.results')."""
        if not path:
            return data
        current = data
        for key in path.split("."):
            if isinstance(current, dict):
                current = current.get(key, {})
            elif isinstance(current, list) and key.isdigit():
                idx = int(key)
                current = current[idx] if idx < len(current) else {}
            else:
                return None
        return current
