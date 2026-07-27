"""
DISCOPE Source — @TTMlogsBot Telegram User Bridge
==================================================
Calls telegram_bridge.py (Telethon) to DM @TTMlogsBot directly as a user.

SETUP (one-time):
  1. pip install telethon
  2. Get api_id + api_hash from https://my.telegram.org
  3. Set env vars or config:
       TG_API_ID=12345
       TG_API_HASH=your_hash
  4. Run once: python telegram_bridge.py --phone "+971XXXXXXXXX"
     → Enter the login code Telegram sends you
  5. Done — now use DISCOPE normally
"""

import json
import logging
import os
import re
import subprocess
import sys
import time

from disma_core.base_source import DataSource, StealerLogRecord

logger = logging.getLogger("disma.source.ttmlogs")

SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BRIDGE_PATH = os.path.join(SCRIPTS_DIR, "telegram_bridge.py")
DATA_DIR = os.path.join(SCRIPTS_DIR, "disma_data")
ATTACHMENTS_DIR = os.path.join(DATA_DIR, "attachments")
os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "tg_sessions"), exist_ok=True)


class Ttmlogs(DataSource):
    """Queries @TTMlogsBot via Telegram User Bridge (Telethon)."""

    def configure(self, config: dict):
        self.name = "ttmlogs"
        self.api_id = config.get("api_id", "") or os.environ.get("TG_API_ID", "")
        self.api_hash = config.get("api_hash", "") or os.environ.get("TG_API_HASH", "")
        self.phone = config.get("phone", "") or os.environ.get("TG_PHONE", "")

    def validate_config(self) -> bool:
        return bool(self.api_id and self.api_hash)

    def fetch(self, domain: str, limit: int = 100) -> list[StealerLogRecord]:
        """Search @TTMlogsBot by domain."""
        if not self.validate_config():
            logger.warning("TTM bridge not configured — set api_id + api_hash in config")
            return []

        records = []
        domain = domain.lower().strip()

        try:
            resp_data = self._call_bridge("--search", domain)
            if not resp_data:
                return records

            records = self._process_bridge_response(domain, resp_data, limit)

        except Exception as e:
            logger.error(f"TTM bridge error: {e}", exc_info=True)

        return records

    def search_email(self, email: str, limit: int = 100) -> list[StealerLogRecord]:
        """Search @TTMlogsBot by email address."""
        if not self.validate_config():
            return []

        records = []
        email = email.lower().strip()
        domain = email.split("@")[1] if "@" in email else email

        try:
            resp_data = self._call_bridge("--search", email)
            if not resp_data:
                return records

            records = self._process_bridge_response(domain, resp_data, limit, is_email=True)

        except Exception as e:
            logger.error(f"TTM email error: {e}")

        return records

    def _call_bridge(self, command: str, query: str) -> dict | None:
        """Call telegram_bridge.py and return parsed JSON response."""
        env = os.environ.copy()
        env["TG_API_ID"] = str(self.api_id)
        env["TG_API_HASH"] = self.api_hash

        try:
            result = subprocess.run(
                [sys.executable if hasattr(sys, 'executable') else "python3",
                 BRIDGE_PATH, command, query],
                capture_output=True, text=True, timeout=120,
                env=env,
            )

            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "telethon not installed" in stderr or "telethon not installed" in result.stdout:
                    logger.error("Telethon not installed. Run: pip install telethon")
                    return None
                logger.warning(f"Bridge returned {result.returncode}: {stderr[:200]}")
                return None

            return json.loads(result.stdout)

        except json.JSONDecodeError as e:
            logger.error(f"Bridge JSON error: {e} — output: {result.stdout[:200]}")
            return None
        except subprocess.TimeoutExpired:
            logger.error("Bridge timed out (60s)")
            return None
        except FileNotFoundError:
            logger.error("telegram_bridge.py not found")
            return None
        except Exception as e:
            logger.error(f"Bridge call error: {e}")
            return None

    def _process_bridge_response(self, domain: str, resp: dict, limit: int, is_email=False) -> list[StealerLogRecord]:
        """Process the bridge's JSON response into records."""
        records = []

        if "error" in resp:
            logger.warning(f"Bridge error: {resp['error']}")
            return records

        if resp.get("type") == "text":
            text = resp.get("text", "")
            records = self._parse_credentials(domain, text, limit)

        elif resp.get("type") == "document":
            file_path = resp.get("file_path", "")
            file_size = resp.get("file_size", 0)
            file_size_mb = file_size / (1024 * 1024)
            preview = resp.get("preview", [])
            extracted_text = resp.get("extracted_text", "")
            total_lines_in_file = resp.get("total_lines", 0)
            is_zip = resp.get("is_zip", False)
            inner_name = resp.get("inner_name", "results.txt")

            if not file_path or not os.path.exists(file_path):
                logger.warning("Bridge returned document but file not found")
                return records

            is_large = file_size_mb > 5

            # Copy to attachments for persistent storage
            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', inner_name if inner_name else os.path.basename(file_path))
            local_path = os.path.join(ATTACHMENTS_DIR, f"ttm_{domain}_{int(time.time())}_{safe_name}")
            try:
                # Copy extracted text or raw file
                with open(file_path, "rb") as src:
                    with open(local_path, "wb") as dst:
                        dst.write(src.read())
            except Exception as e:
                logger.error(f"Failed to copy file: {e}")
                local_path = file_path

            # File reference record
            records.append(StealerLogRecord(
                domain=domain,
                source=self.name,
                record_type="stealer_log",
                content=f"[File: {safe_name}, {file_size_mb:.1f}MB, {total_lines_in_file} lines] TTM results for {domain}",
                severity="critical" if file_size_mb > 0 else "low",
                metadata={
                    "file_type": "telegram_document",
                    "file_path": local_path,
                    "file_name": safe_name,
                    "file_size": file_size,
                    "file_size_mb": round(file_size_mb, 1),
                    "is_large": is_large,
                    "total_lines": total_lines_in_file,
                },
            ))

            # Parse credentials from extracted_text (or from file content)
            if extracted_text:
                for line in extracted_text.split("\n"):
                    if len(records) >= limit + 1:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # Try url:email:password format
                    m = re.match(r'https?://[^:]+:([^@]+@[^:]+):(.+)', line)
                    if m:
                        email = m.group(1)
                        password = m.group(2)
                        rec_domain = email.split("@")[1] if "@" in email else domain
                        records.append(StealerLogRecord(
                            domain=rec_domain,
                            source=self.name,
                            record_type="credential_leak",
                            content=f"Email: {email} | Password: {password[:100]}",
                            severity="critical",
                            metadata={"email": email, "password": password, "source": "@TTMlogsBot"},
                        ))
                        continue
                    # Try email:password format
                    m = re.match(r'([\w.+-]+@[\w-]+\.[\w.-]+)\s*[:;]\s*(.+)', line)
                    if m:
                        email = m.group(1)
                        password = m.group(2)
                        rec_domain = email.split("@")[1]
                        records.append(StealerLogRecord(
                            domain=rec_domain,
                            source=self.name,
                            record_type="credential_leak",
                            content=f"Email: {email} | Password: {password[:100]}",
                            severity="critical",
                            metadata={"email": email, "password": password, "source": "@TTMlogsBot"},
                        ))

        return records

    def _parse_credentials(self, domain: str, text: str, limit: int) -> list[StealerLogRecord]:
        """Extract credentials or hash results from text."""
        records = []
        count = 0

        lines = text.strip().split("\n")
        
        if not lines or all(not l.strip() for l in lines):
            return records

        # Check if there are any email:password patterns
        for line in lines:
            if count >= limit:
                break
            m = re.match(r'([\w.+-]+@[\w-]+\.[\w.-]+)\s*[:;]\s*(.+)', line.strip())
            if m:
                email = m.group(1)
                password = m.group(2)
                rec_domain = email.split("@")[1]
                records.append(StealerLogRecord(
                    domain=rec_domain,
                    source=self.name,
                    record_type="credential_leak",
                    content=f"Email: {email} | Password: {password[:100]}",
                    severity="critical",
                    metadata={"email": email, "password": password, "source": "@TTMlogsBot"},
                ))
                count += 1

        # If no credentials parsed but there's meaningful text, create a generic record
        if not records and len(text) > 5:
            status = text[:500].replace("\n", " | ")
            records.append(StealerLogRecord(
                domain=domain,
                source=self.name,
                record_type="stealer_log",
                content=f"TTM result: {status}",
                severity="info",
                metadata={"source": "@TTMlogsBot", "raw": text[:2000]},
            ))

        return records
