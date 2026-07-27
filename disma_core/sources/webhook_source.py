"""
DISMA Source — Webhook Receiver
Receives stealer log data pushed from external services.
External services POST JSON data to the webhook endpoint.
"""

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

from disma_core.base_source import DataSource, StealerLogRecord

logger = logging.getLogger("disma.source.webhook")


class WebhookSource(DataSource):
    """
    Webhook receiver — external services can push stealer log data here.
    
    How to use:
    1. Enable in config.yaml
    2. Configure external service to POST to http://your-server:9090/webhook
    3. Data format: JSON array of objects with domain/content/type fields
    
    Security: Set an api_key in config to authenticate incoming webhooks.
    """

    def configure(self, config: dict):
        self.listen_port = config.get("listen_port", 9090)
        self.listen_path = config.get("listen_path", "/webhook")
        self.api_key = config.get("api_key", "")
        self.batch_size = config.get("batch_size", 1000)
        self._server = None
        self._thread = None
        self._buffer = []

    def fetch(self, domain: str, limit: int = 100) -> list[StealerLogRecord]:
        """
        Webhook source doesn't actively fetch — it receives data.
        This method returns buffered data matching the domain.
        """
        records = []
        domain_clean = domain.lower().strip()
        matched = []

        for record in self._buffer:
            if domain_clean in record.domain.lower():
                matched.append(record)

        # Remove matched from buffer (consume it)
        self._buffer = [r for r in self._buffer if r not in matched]
        return matched[:limit]

    def start_server(self):
        """Start the webhook listener in a background thread."""
        if self._server:
            return

        class WebhookHandler(BaseHTTPRequestHandler):
            source = self

            def do_POST(self):
                if self.path != self.source.listen_path:
                    self.send_response(404)
                    self.end_headers()
                    return

                # Auth check
                if self.source.api_key:
                    auth = self.headers.get("Authorization", "")
                    if auth != f"Bearer {self.source.api_key}":
                        self.send_response(401)
                        self.end_headers()
                        self.wfile.write(b'{"error": "unauthorized"}')
                        return

                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)

                try:
                    data = json.loads(body)
                    if isinstance(data, dict):
                        data = [data]

                    records = []
                    for item in data:
                        records.append(StealerLogRecord(
                            domain=str(item.get("domain", "unknown")),
                            source=str(item.get("source", "webhook")),
                            record_type=str(item.get("type", "mention")),
                            content=str(item.get("content", "")),
                            url=str(item.get("url", "")),
                            severity=str(item.get("severity", "info")),
                        ))

                    self.source._buffer.extend(records)

                    # Auto-flush to DB if batch size reached
                    if len(self.source._buffer) >= self.source.batch_size:
                        self.source._flush_to_db()

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "status": "ok",
                        "received": len(records),
                    }).encode())

                except json.JSONDecodeError:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error": "invalid JSON"}')

            def log_message(self, format, *args):
                pass

        self._server = HTTPServer(("0.0.0.0", self.listen_port), WebhookHandler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"Webhook source listening on :{self.listen_port}{self.listen_path}")

    def _flush_to_db(self):
        """Flush buffered records to the database."""
        if not self._buffer:
            return
        from disma_core.database import DatabaseEngine
        db = DatabaseEngine()
        count = db.insert_batch(self._buffer)
        logger.info(f"Webhook: flushed {count} records to database")
        self._buffer = []

    def stop_server(self):
        """Stop the webhook listener."""
        if self._server:
            self._server.shutdown()
            self._server = None
            logger.info("Webhook source stopped")
