"""
DISMA Source — Telegram Bot / Client
Monitors Telegram channels and groups for stealer log mentions.

Requires one of:
  A) Bot Token (simpler) — monitors channels the bot is added to
  B) API ID + Hash (user client) — monitors any accessible chat

Configuration in disma_config.yaml:
  sources:
    telegram:
      enabled: true
      bot_token: "YOUR_BOT_TOKEN"
      chat_ids: ["-1001234567890"]
      keywords: ["stealer", "log", "leak", "combo"]
"""

import logging
import re
import time
from datetime import datetime, timezone

from disma_core.base_source import DataSource, StealerLogRecord

logger = logging.getLogger("disma.source.telegram")


class TelegramSource(DataSource):
    """
    Telegram monitor for stealer log mentions.
    
    HOW TO SET UP (when you have an API key):
    
    1. Bot Token method (simpler):
       - Create a bot via @BotFather on Telegram
       - Add bot to target channels/groups
       - Set bot_token in config
       - Bot will receive forwarded messages
    
    2. API ID + Hash method (user client):
       - Get api_id and api_hash from https://my.telegram.org
       - Set phone, api_id, api_hash in config
       - First run will ask for verification code
    """

    def configure(self, config: dict):
        self.bot_token = config.get("bot_token", "")
        self.api_id = config.get("api_id", "")
        self.api_hash = config.get("api_hash", "")
        self.phone = config.get("phone", "")
        self.chat_ids = config.get("chat_ids", [])
        self.keywords = config.get("keywords", ["stealer", "log", "leak", "combo"])
        self.session_file = config.get("session_file", "disma_data/telegram_session")
        self.monitor_interval = config.get("monitor_interval_minutes", 15)
        self.max_history = config.get("max_history_messages", 1000)

    def fetch(self, domain: str, limit: int = 100) -> list[StealerLogRecord]:
        """
        Search Telegram messages for the target domain.
        
        Uses Telegram's search API via bot (no Telethon dependency needed).
        Falls back to searching public Telegram channels via Google.
        """
        records = []
        domain_clean = domain.lower().strip()

        # Method 1: Bot API (if configured)
        if self.bot_token:
            try:
                records = self._fetch_via_bot(domain_clean, limit)
            except Exception as e:
                logger.warning(f"Telegram bot fetch failed: {e}")

        # Method 2: Public channel search via web (no API key needed)
        if not records:
            try:
                records = self._fetch_via_web(domain_clean, limit)
            except Exception as e:
                logger.warning(f"Telegram web search failed: {e}")

        return records

    def _fetch_via_bot(self, domain: str, limit: int) -> list[StealerLogRecord]:
        """Fetch using Telegram Bot API."""
        records = []
        
        if not self.chat_ids:
            logger.warning("No chat_ids configured for Telegram bot")
            return records

        # Using bot API via HTTP (no python-telegram-bot dependency needed)
        for chat_id in self.chat_ids[:5]:
            try:
                import subprocess
                import json

                # Get chat history via Bot API
                url = f"https://api.telegram.org/bot{self.bot_token}/getChatHistory"
                data = {
                    "chat_id": chat_id,
                    "limit": min(limit, 100),
                }

                result = subprocess.run(
                    ["curl", "-sk", "--max-time", "15",
                     "-X", "POST", url,
                     "-H", "Content-Type: application/json",
                     "-d", json.dumps(data)],
                    capture_output=True, text=True, timeout=20,
                )

                response = json.loads(result.stdout)
                if response.get("ok"):
                    for msg in response.get("result", []):
                        text = msg.get("text", "") or msg.get("caption", "") or ""
                        if domain.lower() in text.lower():
                            records.append(StealerLogRecord(
                                domain=domain,
                                source=self.name,
                                record_type=self._classify(text),
                                content=text[:10000],
                                url=f"https://t.me/c/{str(chat_id).replace('-100', '')}/{msg.get('message_id', '')}",
                                severity="critical" if "stealer" in text.lower() else "warning",
                                metadata={"chat_id": str(chat_id), "message_id": msg.get("message_id")},
                            ))

            except Exception as e:
                logger.warning(f"Bot fetch for chat {chat_id} failed: {e}")

        return records

    def _fetch_via_web(self, domain: str, limit: int) -> list[StealerLogRecord]:
        """Search Telegram via web/Google as fallback."""
        records = []

        try:
            import subprocess
            from urllib.parse import quote_plus

            query = f"site:t.me {domain} stealer OR log OR leak OR combo"
            url = f"https://www.google.com/search?q={quote_plus(query)}"

            result = subprocess.run(
                ["curl", "-sk", "--max-time", "15",
                 "-L", "-A",
                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                 url],
                capture_output=True, text=True, timeout=20,
            )

            text = result.stdout
            found_urls = re.findall(r'(https?://t\.me/[a-zA-Z0-9_/]+)', text)

            for telegram_url in found_urls[:limit]:
                records.append(StealerLogRecord(
                    domain=domain,
                    source=self.name,
                    record_type="mention",
                    content=f"Mentioned in Telegram: {telegram_url}",
                    url=telegram_url,
                    severity="info",
                    metadata={"found_via": "web_search", "url": telegram_url},
                ))

        except Exception as e:
            logger.warning(f"Telegram web search failed: {e}")

        return records

    def _classify(self, text: str) -> str:
        t = text.lower()
        if any(kw in t for kw in ["redline", "vidar", "lumma", "stealc", "raccoon"]):
            return "stealer_log"
        if any(kw in t for kw in ["pass", "email:", "login:", "credential", "combo"]):
            return "credential_leak"
        return "mention"
