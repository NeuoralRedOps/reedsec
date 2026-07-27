"""
DISMA Source — Ahmia (.onion / Dark Web Search)
Searches Ahmia search engine for .onion mentions of target domains.

Note: Requires Tor running locally for full .onion access.
Without Tor, searches the clearnet Ahmia index.
"""

import json
import logging
import subprocess
from urllib.parse import quote_plus

from disma_core.base_source import DataSource, StealerLogRecord

logger = logging.getLogger("disma.source.ahmia")


class AhmiaSource(DataSource):
    """Searches Ahmia (dark web search engine) for domain mentions."""

    def configure(self, config: dict):
        self.onion_endpoint = config.get("onion_endpoint", "")
        self.timeout = config.get("timeout", 30)
        self.max_results = config.get("max_results", 100)

    def fetch(self, domain: str, limit: int = 100) -> list[StealerLogRecord]:
        records = []
        domain_clean = domain.lower().strip()
        limit = min(limit, self.max_results)

        try:
            # Ahmia clearnet search
            url = f"https://ahmia.fi/search/?q={quote_plus(domain_clean)}"

            result = subprocess.run(
                ["curl", "-sk", "--max-time", str(self.timeout),
                 "-L", "-A",
                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                 url],
                capture_output=True, text=True, timeout=self.timeout + 5,
            )

            text = result.stdout

            # Extract .onion URLs mentioning the domain
            import re
            onion_urls = re.findall(r'(https?://[a-z2-7]{16,56}\.onion[^\s"<>]*)', text)
            domain_mentions = re.findall(
                rf'([^\s<>"]*{re.escape(domain_clean)}[^\s<>"]*)', text
            )

            # Create records from .onion links found
            for onion_url in onion_urls[:limit]:
                records.append(StealerLogRecord(
                    domain=domain_clean,
                    source=self.name,
                    record_type="mention",
                    content=f"Found on dark web: {onion_url[:200]}",
                    url=onion_url,
                    severity="warning",
                    metadata={"source": "ahmia_onion", "url": onion_url},
                ))

            # Create records from domain mentions in results
            for mention in domain_mentions[:limit]:
                records.append(StealerLogRecord(
                    domain=domain_clean,
                    source=self.name,
                    record_type="mention",
                    content=f"Mentioned in Ahmia results: {mention[:500]}",
                    url="https://ahmia.fi",
                    severity="info",
                    metadata={"source": "ahmia", "snippet": mention[:200]},
                ))

        except subprocess.TimeoutExpired:
            logger.warning(f"Ahmia search timed out for {domain}")
        except Exception as e:
            logger.warning(f"Ahmia search error for {domain}: {e}")

        return records
