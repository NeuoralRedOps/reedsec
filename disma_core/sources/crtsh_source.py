"""
DISMA Source — CRT.sh (Certificate Transparency)
Fetches subdomains and domain mentions from Certificate Transparency logs.
"""

import json
import logging
import subprocess
import time

from disma_core.base_source import DataSource, StealerLogRecord

logger = logging.getLogger("disma.source.crtsh")


class CrtshSource(DataSource):
    """Queries crt.sh for subdomain mentions of the target domain."""

    def configure(self, config: dict):
        self.endpoint = config.get("endpoint", "https://crt.sh")
        self.timeout = config.get("timeout", 30)
        self.max_results = config.get("max_results", 500)

    def fetch(self, domain: str, limit: int = 500) -> list[StealerLogRecord]:
        records = []
        limit = min(limit, self.max_results)
        domain_clean = domain.lower().strip()

        try:
            url = f"{self.endpoint}/?q=%25.{domain_clean}&output=json"
            result = subprocess.run(
                ["curl", "-sk", "--max-time", str(self.timeout),
                 "-H", "Accept: application/json", url],
                capture_output=True, text=True, timeout=self.timeout + 5,
            )

            if not result.stdout or result.stdout.strip().startswith("<!DOCTYPE"):
                # Try alternative endpoint
                url = f"https://crt.sh/json?q=%25.{domain_clean}"
                result = subprocess.run(
                    ["curl", "-sk", "--max-time", str(self.timeout), url],
                    capture_output=True, text=True, timeout=self.timeout + 5,
                )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        seen = set()
                        for entry in data[:limit]:
                            name_value = entry.get("name_value", "") or ""
                            # CRT.sh sometimes returns comma-separated names
                            for subdomain in name_value.split("\n"):
                                subdomain = subdomain.strip().lower()
                                if not subdomain or subdomain in seen:
                                    continue
                                seen.add(subdomain)

                                if domain_clean in subdomain:
                                    records.append(StealerLogRecord(
                                        domain=domain_clean,
                                        source=self.name,
                                        record_type="mention",
                                        content=f"Subdomain found: {subdomain}",
                                        url=f"https://crt.sh/?q={subdomain}",
                                        severity="info",
                                        metadata={
                                            "subdomain": subdomain,
                                            "issuer": entry.get("issuer_name", ""),
                                            "not_after": entry.get("not_after", ""),
                                        },
                                    ))

                except json.JSONDecodeError:
                    logger.warning(f"CRT.sh returned non-JSON for {domain}")

        except subprocess.TimeoutExpired:
            logger.warning(f"CRT.sh timed out for {domain}")
        except Exception as e:
            logger.warning(f"CRT.sh error for {domain}: {e}")

        return records
