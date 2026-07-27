"""
DISMA Source — Pastebin Scraper
Scrapes pastebin.com for mentions of target domains.
"""

import logging
import re
import subprocess
import sys
import time
from urllib.parse import quote_plus

from disma_core.base_source import DataSource, StealerLogRecord

logger = logging.getLogger("disma.source.pastebin")


class PastebinSource(DataSource):
    """Scrapes Pastebin for stealer logs mentioning target domains."""

    def configure(self, config: dict):
        self.rate_limit = config.get("rate_limit_delay", 2)
        self.timeout = config.get("timeout", 15)
        self.max_results = config.get("max_results", 100)
        self.last_request = 0.0

    def fetch(self, domain: str, limit: int = 100) -> list[StealerLogRecord]:
        records = []
        domain_clean = domain.lower().strip()
        limit = min(limit, self.max_results)

        # Throttle requests
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)

        try:
            # Search pastebin via Google/Bing
            search_urls = [
                f"https://www.google.com/search?q=site:pastebin.com+{quote_plus(domain_clean)}",
            ]

            for url in search_urls:
                self.last_request = time.time()
                result = subprocess.run(
                    [
                        "curl", "-sk", "--max-time", str(self.timeout),
                        "-L", "-A",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        url,
                    ],
                    capture_output=True, text=True, timeout=self.timeout + 5,
                )

                text = (result.stdout or "") + (result.stderr or "")

                # Extract paste URLs
                paste_urls = re.findall(r'(https?://pastebin\.com/(?!raw|search|login|signup|api)[a-zA-Z0-9]{8,16})', text)

                for paste_url in paste_urls[:limit]:
                    time.sleep(self.rate_limit)
                    # Fetch each paste
                    raw_url = paste_url.replace("pastebin.com/", "pastebin.com/raw/")
                    self.last_request = time.time()
                    paste_result = subprocess.run(
                        ["curl", "-sk", "--max-time", "10", raw_url],
                        capture_output=True, text=True, timeout=15,
                    )
                    content = (paste_result.stdout or "").strip()

                    if domain_clean in content.lower():
                        records.append(StealerLogRecord(
                            domain=domain_clean,
                            source=self.name,
                            record_type=self._detect_type(content),
                            content=content[:10000],
                            url=paste_url,
                            severity=self._detect_severity(content),
                            metadata={"found_via": "pastebin_search"},
                        ))

                    if len(records) >= limit:
                        break

        except subprocess.TimeoutExpired:
            logger.warning(f"Pastebin search timed out for {domain}")
        except Exception as e:
            logger.warning(f"Pastebin search error for {domain}: {e}")

        return records

    def _detect_type(self, content: str) -> str:
        c = content.lower()
        if any(kw in c for kw in ["redline", "vidar", "raccoon", "lumma", "stealc",
                                    "agenttesla", "azorult", "risepro", "warzone"]):
            return "stealer_log"
        if any(kw in c for kw in ["password", "email", "pass:", "login:", "credential"]):
            return "credential_leak"
        return "mention"

    def _detect_severity(self, content: str) -> str:
        c = content.lower()
        if any(kw in c for kw in ["redline", "vidar", "lumma"]):
            return "critical"
        if any(kw in c for kw in ["password", "pass:", "email:pass"]):
            return "warning"
        return "info"
