#!/usr/bin/env python3
"""
DISCOPE — AI-Powered Agent
=============================
A REAL generative AI chatbot for stealer log scanning.
Uses the modular DISCOPE Core engine + plugin system.

Usage:
  python agent_server.py [--port 8080]

Then open http://localhost:8080 in your browser.
"""

import http.server
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import ssl
from datetime import datetime, timezone

# ── DISCOPE Engine ──────────────────────────────────────────────
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

from disma_core.engine import DISMAEngine
from disma_core.base_source import StealerLogRecord
from disma_core.semantic import SemanticStore
from disma_core.mitre_mapper import generate_mitre_report

PORT = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--port" else 8080

ENGINE = DISMAEngine()
ENGINE.load_config(os.path.join(SCRIPTS_DIR, "disma_config.yaml"))
ENGINE.auto_discover_sources()

# Semantic search layer (embeddings over the logs table)
SEMANTIC = SemanticStore(os.path.join(SCRIPTS_DIR, "disma_data", "stealer_logs.db"))

# Server-side conversation sessions: session_id -> [messages]
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
SESSION_MAX_MESSAGES = 40

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("disma.agent")

# ── AI Model Setup ─────────────────────────────────────────────────────────────

AI_API_URL = "https://inference-api.nousresearch.com/v1"
# Use laguna-s as primary (more reliable free-tier responses); xs works but
# frequently returns empty choices arrays due to free-tier rate limits.
AI_MODEL = "poolside/laguna-s-2.1:free"
AI_TOKEN = None

auth_path = os.path.join(os.path.dirname(SCRIPTS_DIR), "auth.json")
if os.path.exists(auth_path):
    try:
        with open(auth_path) as f:
            data = json.load(f)
            AI_TOKEN = data.get("agent_key") or data.get("api_key") or data.get("token")
            if not AI_TOKEN:
                # Hermes auth.json format
                provider = data.get("providers", {}).get("nous", {})
                AI_TOKEN = provider.get("access_token") or provider.get("api_key")
            if not AI_TOKEN:
                # Credential pool
                pool = data.get("credential_pool", {})
                for key in pool:
                    entries = pool[key]
                    if entries and isinstance(entries, list):
                        entry = entries[0]
                        AI_TOKEN = entry.get("api_key") or entry.get("token")
                        if AI_TOKEN:
                            break
    except Exception:
        pass

if not AI_TOKEN:
    AI_TOKEN = os.environ.get("NOUS_API_KEY", "")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ── AI Call ────────────────────────────────────────────────────────────────────
# ── AI Call ────────────────────────────────────────────────────────────────────

_AI_LOCK = threading.Lock()
_LAST_AI_CALL_TS = [0.0]
_MIN_GAP_SECONDS = 3.0  # reduced from 6s — faster response, still respectful

# Provider configs — OpenRouter primary, Nous fallback
_PROVIDERS = [
    {
        "name": "openrouter",
        "url": "https://openrouter.ai/api/v1",
        "token": os.environ.get("OPENROUTER_API_KEY", ""),
        "models": [
            "xiaomi/mimo-v2.5",
            "deepseek/deepseek-v4-flash",
            "nvidia/nemotron-3-ultra-550b-a55b:free",
        ],
    },
    {
        "name": "nous",
        "url": "https://inference-api.nousresearch.com/v1",
        "token": AI_TOKEN,
        "models": [
            "poolside/laguna-s-2.1:free",
            "poolside/laguna-xs-2.1:free",
            "nousresearch/hermes-3.1:free",
        ],
    },
]

def call_ai(messages: list, max_tokens: int = 600, system_prompt: str = None) -> str:
    """Call AI with multi-provider fallback, retry+backoff, and rate gating.
    Never returns an error string to the user — always returns usable content."""
    if not AI_TOKEN:
        return _local_fallback(messages, system_prompt)

    with _AI_LOCK:
        last_ts = _LAST_AI_CALL_TS[0]
        now = time.time()
        gap = now - last_ts
        if gap < _MIN_GAP_SECONDS:
            time.sleep(_MIN_GAP_SECONDS - gap)
        _LAST_AI_CALL_TS[0] = time.time()
        result = _call_ai_multi_provider(messages, max_tokens, system_prompt)

    # If all providers failed, use local fallback — user never sees an error
    if result is None:
        return _local_fallback(messages, system_prompt)
    return result


def _call_ai_multi_provider(messages, max_tokens, system_prompt):
    """Try each provider in order, with model fallback within each.
    Returns content string on success, None on total failure."""
    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    for provider in _PROVIDERS:
        token = provider["token"]
        if not token:
            continue

        for model in provider["models"]:
            result = _try_model(
                provider["url"], token, model, full_messages, max_tokens,
                provider_name=provider["name"],
            )
            if result is not None and result != "RATE_LIMIT":
                return result
            # On rate limit, try next model immediately (no sleep)
            if result == "RATE_LIMIT":
                continue

    return None


def _try_once(model):
    """Legacy wrapper for backward compatibility."""
    return _try_model(AI_API_URL, AI_TOKEN, model, [], 600)


def _try_model(base_url, token, model, messages, max_tokens, provider_name=""):
    """Single attempt against a specific provider+model. Returns content, RATE_LIMIT, or None."""
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
    })
    headers = [
        "-H", f"Authorization: Bearer {token}",
        "-H", "Content-Type: application/json",
        "-H", "User-Agent: Hermes-Agent",
    ]
    # OpenRouter requires referer header
    if "openrouter" in base_url:
        headers.extend(["-H", "HTTP-Referer: https://discope.local"])
        headers.extend(["-H", "X-Title: DISCOPE"])

    curl_args = [
        "curl", "-sk", "--max-time", "20",
    ] + headers + [
        "-d", payload,
        f"{base_url}/chat/completions",
    ]
    try:
        proc = subprocess.run(curl_args, capture_output=True, text=True, timeout=25)
        if proc.returncode != 0:
            return None
        result = json.loads(proc.stdout)
        if "error" in result:
            code = result["error"].get("code", "")
            if code in (504, 429, 503, 502):
                return "RATE_LIMIT"
            return None
        choices = result.get("choices")
        if not choices or not isinstance(choices, list) or len(choices) == 0:
            return None
        msg = choices[0].get("message", {})
        content = (msg.get("content") or "").strip()
        reasoning = (msg.get("reasoning") or "").strip()
        # Prefer content over reasoning — reasoning is the model's internal monologue
        if content:
            return content
        if reasoning:
            return reasoning
        return None
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        return None


def _local_fallback(messages, system_prompt):
    """Local template responses when all AI providers are down.
    Ensures the chatbot NEVER returns an error to the user."""
    last_user = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            last_user = m.get("content", "").lower()
            break

    # Scan-related
    if any(w in last_user for w in ["scan", "check", "domain", "leak", "breach"]):
        return (
            "I'm having trouble connecting to the AI model right now, but I can still scan domains. "
            "Just type `scan <domain>` and I'll run it against our threat intelligence sources."
        )

    # Greeting
    if any(w in last_user for w in ["hi", "hello", "hey", "good morning", "good evening"]):
        return (
            "Hey! I'm DISCOPE — your threat intelligence agent. I scan domains for stealer logs "
            "and credential leaks. What domain can I check for you?"
        )

    # Help
    if any(w in last_user for w in ["help", "what can you do", "how", "command"]):
        return (
            "Here's what I can do:\n"
            "• `scan <domain>` — check for stealer logs and credential leaks\n"
            "• `scan fresh <domain>` — force a live re-scan\n"
            "• Ask questions about data we've already indexed\n"
            "Just give me a domain to get started."
        )

    # Default
    return (
        "I'm running on local fallback right now (AI model temporarily unavailable). "
        "I can still scan domains — just type `scan <domain>` and I'll check it against "
        "our threat intelligence sources."
    )


# ── System Prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are **DISCOPE AGENT** — a threat intelligence scanning agent. You scan domains for stealer logs and credential leaks. That's your purpose.

## PERSONALITY
- You are a REAL generative AI, not a scripted bot. Be warm, natural, and conversational.
- If someone says their name, use it! "Hey Akshay, good to meet you!"
- Respond naturally — short sentences, varied tone, real personality.
- Feel like a smart friend who happens to be a security expert.

## SCOPE — You ONLY do ONE thing: scan domains for stealer logs.
- If the user asks something unrelated (cooking, sports, history, etc.), politely redirect to scanning. Don't provide that info.
- The user might phrase requirements casually. Understand the INTENT, not just keywords.

## COMMANDS you support
- `scan <domain>` — run a fresh stealer-log + leak scan across our threat sources
- `scan fresh <domain>` — bypass cache, force live re-scan
- casual questions about findings, threats, sources, what you can do
- Anything outside this scope: redirect to "I can only help with scanning domains."

## RESPONSE STYLE
- Always warm + conversational.
- Acknowledge name when given. ("Hey Akshay, ...")
- After scan: report findings in 2–4 short sentences max. No big tables.
- Be a friend — not a robot.

## FULL DOMAIN SCANS
For heavy scans (TTM stealer logs, etc.) you don't respond yourself — the engine handles results. Just acknowledge and let it run.

Remember: warm, real, security-expert friend.
"""


# ── Helper Parsers ──────────────────────────────────────────────────────────────

def extract_domain(text: str):
    """Extract a domain from free text."""
    m = re.search(r'([\w.-]+\.[\w]{2,})', text.strip())
    if m:
        return m.group(1).lower()
    return None

def extract_email(text: str):
    """Extract a full email address from text."""
    m = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', text.strip())
    if m:
        return m.group(0).lower()
    return None

def has_scan_intent(text: str) -> bool:
    t = text.lower()
    if re.search(r'\b(scan|check|look\s*up|search|find|investigate|monitor|hunt)\b', t):
        return True
    # domain alone counts as scan request
    if extract_domain(text):
        # is it phrased like a domain-only query? "dewa.gov.ae"
        # check that there's no other word content
        tokens = text.strip().split()
        if len(tokens) == 1 and '.' in tokens[0]:
            return True
    return False


def has_query_intent(text: str) -> bool:
    """Detect natural-language questions about already-indexed data (RAG queries).
    Distinct from scan intent — these ask ABOUT findings, not trigger new scans.
    Conservative: only returns True when the question is clearly about the data."""
    t = text.lower()
    # Must reference data concepts — pure question words aren't enough
    data_keywords = (
        r'\b(credentials?|passwords?|emails?|logins?|leaks?|logs?|findings?|'
        r'results?|breaches?|compromised?|stolen|hacked?|dumped?|exposed|'
        r'accounts?|usernames?)\b'
    )
    if not re.search(data_keywords, t):
        return False
    # Question starters or imperative "show me"
    if re.search(r'\b(what|which|who|show|list|tell|how many|did|were|was|are there|is there|give|find)\b', t):
        return True
    return False


def semantic_query(question: str, session_id: str = "default",
                   domain_filter: str = None, top_k: int = 5) -> dict:
    """Full RAG pipeline: embed question → retrieve chunks → LLM synthesis.
    Returns {answer, sources, response_ms}."""
    import uuid
    start = time.time()

    # Make sure newly-ingested logs are indexed
    try:
        SEMANTIC.index_pending(limit=100)
    except Exception as e:
        logger.warning(f"index_pending failed: {e}")

    hits = SEMANTIC.query(question, top_k=top_k, domain_filter=domain_filter)

    if not hits:
        return {
            "answer": "I don't have indexed data matching that yet. Try scanning a domain first to populate the index.",
            "sources": [],
            "response_ms": int((time.time() - start) * 1000),
        }

    # Build context from retrieved chunks
    context_parts = []
    sources = []
    for i, h in enumerate(hits):
        context_parts.append(
            f"[{i+1}] (source={h['source']}, domain={h['domain']})\n{h['preview']}"
        )
        sources.append({
            "chunk_id": h["chunk_id"],
            "log_id": h["log_id"],
            "domain": h["domain"],
            "source": h["source"],
            "relevance": round(h["score"], 3),
            "preview": h["preview"][:160],
        })
    context = "\n\n".join(context_parts)

    rag_prompt = (
        "You are DISCOPE, a security log analyst. Answer the user's question using ONLY "
        "the retrieved log excerpts below. Be specific — include emails, URLs, or "
        "credentials when they appear in the context. If the question is unrelated to "
        "the excerpts (e.g. sports, weather, general knowledge), respond with exactly: "
        "\"That's outside the scope of the indexed data. I can only answer questions "
        "about stealer logs and credential leaks we've scanned.\" Do NOT describe what's "
        "in the logs for off-topic questions. Keep on-topic answers under 5 sentences. "
        "Never reveal source names beyond generic terms.\n\n"
        f"Retrieved excerpts:\n{context}\n\n"
        f"Question: {question}"
    )

    answer = call_ai(
        messages=[{"role": "user", "content": rag_prompt}],
        max_tokens=400,
    )

    ms = int((time.time() - start) * 1000)
    try:
        SEMANTIC.log_query(session_id, question, answer, sources, ms)
    except Exception as e:
        logger.warning(f"log_query failed: {e}")

    return {"answer": answer, "sources": sources, "response_ms": ms}


# ── Scanner Integration ────────────────────────────────────────────────────────

def run_scanner(domain: str, email: str = None, _bypass_cache: bool = False) -> dict:
    result = ENGINE.scan_domain(domain, bypass_cache=_bypass_cache)

    # Also search by email if provided (mostly for ttmlogs source)
    if email:
        for source in ENGINE.registry.get_enabled():
            if hasattr(source, 'search_email'):
                try:
                    email_records = source.search_email(email)
                    if email_records:
                        for r in email_records:
                            ENGINE.db.insert_record(r)
                        result.setdefault("records", []).extend(email_records)
                        result["total_found"] = result.get("total_found", 0) + len(email_records)
                        result["critical"] = result.get("critical", 0) + len(email_records)
                        result["credential_leaks"] = result.get("credential_leaks", 0) + len(email_records)
                except Exception as e:
                    logger.warning(f"Email search failed on {source.name}: {e}")

    return {
        "success": True,
        "summary": result,
        "has_critical": result.get("critical", 0) > 0,
        "has_leak": result.get("credential_leaks", 0) > 0 or result.get("total_found", 0) > 0,
        "records": result.get("records", []),
        "records_count": result.get("total_found", 0),
        **({"error": str(result)} if not result else {})
    }


# ── HTML Chat UI ───────────────────────────────────────────────────────────────

_CHAT_UI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chat_ui_new.html')
try:
    with open(_CHAT_UI_PATH, 'r', encoding='utf-8') as _f:
        CHAT_UI = _f.read()
except Exception:
    CHAT_UI = '<!DOCTYPE html><html><body><h1>DISCOPE — UI not loaded</h1></body></html>'


# ── HTTP Handler ───────────────────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "DISCOPE/1.0"

    def _json(self, data, status=200):
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            self.wfile.write(json.dumps(data, default=str).encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            try:
                self.wfile.write(b'{"status":"error"}')
            except Exception:
                pass

    def log_message(self, format, *args):
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            msg = format % args if args else format
        except Exception:
            msg = str(args) if args else format
        sys.stderr.write(f"[{ts}] {msg}\n")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(CHAT_UI.encode("utf-8"))
            return
        if parsed.path == "/api/health":
            sources_online = len([s for s in ENGINE.registry.get_enabled()])
            sem_stats = SEMANTIC.stats()
            self._json({
                "status": "ok",
                "ai": bool(AI_TOKEN),
                "sources": sources_online,
                "records": ENGINE.db.get_stats().get("total_records", 0),
                "semantic": sem_stats,
            })
            return
        if parsed.path == "/api/sources":
            srcs = []
            # Per-source counts via direct SQL (FTS5 table has no source column)
            per_source = {}
            try:
                import sqlite3
                conn = sqlite3.connect(ENGINE.db.db_path, timeout=5)
                for row in conn.execute(
                    "SELECT source, COUNT(*) FROM logs GROUP BY source"
                ):
                    per_source[row[0]] = row[1]
                conn.close()
            except Exception:
                pass
            for s in ENGINE.registry.all():
                srcs.append({
                    "name": s.name,
                    "type": s.__class__.__name__,
                    "enabled": s.enabled,
                    "configured": s.validate_config(),
                    "records": per_source.get(s.name, 0),
                })
            self._json({"status": "ok", "sources": srcs})
            return
        if parsed.path == "/api/stats":
            try:
                db_stats = ENGINE.db.get_stats()
                sem_stats = SEMANTIC.stats()
                per_source = {}
                import sqlite3
                conn = sqlite3.connect(ENGINE.db.db_path, timeout=5)
                for row in conn.execute(
                    "SELECT source, COUNT(*) FROM logs GROUP BY source"
                ):
                    per_source[row[0]] = row[1]
                conn.close()
                self._json({
                    "status": "ok",
                    "database": db_stats,
                    "semantic": sem_stats,
                    "sources": per_source,
                })
            except Exception as e:
                self._json({"status": "error", "error": str(e)}, 500)
            return
        if parsed.path == "/api/documents":
            params = urllib.parse.parse_qs(parsed.query)
            limit = int(params.get("limit", ["50"])[0])
            offset = int(params.get("offset", ["0"])[0])
            domain_f = params.get("domain", [None])[0]
            try:
                if domain_f:
                    recs = ENGINE.db.search_by_domain(domain_f, limit=limit, offset=offset)
                    total = ENGINE.db.count_by_domain(domain_f).get("total", 0)
                else:
                    recs = []
                    for batch in ENGINE.db.stream_all(batch_size=limit + offset):
                        recs = batch[offset:offset + limit]
                        break
                    total = ENGINE.db.get_stats().get("total_records", 0)
                docs = []
                for r in recs:
                    docs.append({
                        "domain": r.domain if hasattr(r, "domain") else r.get("domain"),
                        "source": r.source if hasattr(r, "source") else r.get("source"),
                        "record_type": r.record_type if hasattr(r, "record_type") else r.get("record_type"),
                        "severity": r.severity if hasattr(r, "severity") else r.get("severity"),
                        "timestamp": r.timestamp if hasattr(r, "timestamp") else r.get("timestamp"),
                        "url": r.url if hasattr(r, "url") else r.get("url"),
                    })
                self._json({"status": "ok", "total": total, "documents": docs})
            except Exception as e:
                self._json({"status": "error", "error": str(e)}, 500)
            return
        if parsed.path == "/api/history":
            params = urllib.parse.parse_qs(parsed.query)
            session_id = params.get("session_id", [None])[0]
            limit = int(params.get("limit", ["50"])[0])
            try:
                rows = SEMANTIC.get_history(session_id=session_id, limit=limit)
                self._json({"status": "ok", "history": rows})
            except Exception as e:
                self._json({"status": "error", "error": str(e)}, 500)
            return
        if parsed.path == "/api/download":
            params = urllib.parse.parse_qs(parsed.query)
            file_path = params.get("path", [""])[0]
            if file_path and os.path.exists(file_path):
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
                    self.send_header("Content-Length", str(file_size))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    with open(file_path, "rb") as f:
                        self.wfile.write(f.read())
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            self._json({"status": "error", "error": "File not found"}, 404)
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        # ── Dedicated RAG query endpoint (PRD §12 /query) ──
        if parsed.path == "/api/semantic/query":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = self.rfile.read(length)
                data = json.loads(body)
            except json.JSONDecodeError:
                self._json({"status": "error", "error": "Invalid JSON"}, 400)
                return
            question = data.get("question", "").strip()
            if not question:
                self._json({"status": "error", "error": "Missing 'question'"}, 400)
                return
            session_id = data.get("session_id", "api")
            top_k = int(data.get("top_k", 5))
            domain_filter = data.get("domain")
            try:
                result = semantic_query(
                    question, session_id=session_id,
                    domain_filter=domain_filter, top_k=top_k,
                )
                self._json({"status": "ok", **result})
            except Exception as e:
                logger.exception("semantic query failed")
                self._json({"status": "error", "error": str(e)}, 500)
            return

        if parsed.path != "/api/chat":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = self.rfile.read(length)
            data = json.loads(body)
        except json.JSONDecodeError:
            self._json({"status": "error", "error": "Invalid JSON"}, 400)
            return

        user_message = data.get("message", "").strip()
        history = data.get("history", [])
        session_id = data.get("session_id") or "default"

        if not user_message:
            self._json({"status": "error", "error": "Empty message"}, 400)
            return

        # Server-side session memory (PRD FR-3.6)
        with SESSIONS_LOCK:
            sess = SESSIONS.setdefault(session_id, [])
            # Merge client history (client is source of truth if longer)
            if len(history) > len(sess):
                sess = list(history)
                SESSIONS[session_id] = sess
            sess.append({"role": "user", "content": user_message})
            # Trim
            if len(sess) > SESSION_MAX_MESSAGES:
                SESSIONS[session_id] = sess[-SESSION_MAX_MESSAGES:]
                sess = SESSIONS[session_id]

        ai_messages = [{"role": m["role"], "content": m["content"]} for m in sess[-20:]]

        domain = extract_domain(user_message)
        is_scan = has_scan_intent(user_message) and domain is not None

        # If NOT a scan but looks like a data question AND we have indexed data,
        # route through RAG instead of plain chat.
        if not is_scan and has_query_intent(user_message):
            stats = SEMANTIC.stats()
            if stats.get("total_chunks", 0) > 0:
                try:
                    result = semantic_query(
                        user_message, session_id=session_id,
                        domain_filter=None, top_k=5,
                    )
                    with SESSIONS_LOCK:
                        SESSIONS[session_id].append(
                            {"role": "assistant", "content": result["answer"]}
                        )
                    self._json({
                        "status": "ok",
                        "response": result["answer"],
                        "is_scan_result": False,
                        "is_rag_result": True,
                        "sources": result["sources"],
                        "response_ms": result["response_ms"],
                        "threat_level": "low",
                        "status_text": "Ready",
                    })
                    return
                except Exception as e:
                    logger.exception("RAG routing failed, falling through to chat")

        # Detect if user wants a fresh/forced rescan (not cached results)
        fresh_keywords = ['fresh', 'rescan', 're-scan', 'again', 'force', 'update',
                         'refresh', 'new scan', 'scan again', 'redo']
        wants_fresh = is_scan and any(kw in user_message.lower() for kw in fresh_keywords)

        if is_scan:
            # Determine whether to use cache or force a fresh live scan
            cached_count = 0
            try:
                cached = ENGINE.db.count_by_domain(domain)
                cached_count = cached.get('total', 0)
            except Exception:
                pass

            if wants_fresh or cached_count == 0:
                # Run a fresh live scan (bypasses cache + clears stale rows for this domain)
                ack_text = f"Scanning {domain} \u2014 querying stealer log sources..."
                self.server._scanning = True
                email = extract_email(user_message)
                scan_result = run_scanner(domain, email=email, _bypass_cache=True)
                self.server._scanning = False
            else:
                # Domain already scanned — serve cached results, NO live scan
                scan_result = run_scanner(domain, email=None)
                scan_result['from_cache'] = True
                ack_text = f"Already scanned. Use 'scan fresh {domain}' to re-scan live."

            if not scan_result["success"]:
                final = f"{ack_text}\n\nSorry, the scan failed: {scan_result['error']}"
                self._json({
                    "status": "ok",
                    "response": final,
                    "is_scan_result": True,
                    "threat_level": "low",
                    "status_text": "Error",
                    "status_state": "error",
                })
                return

            summary = scan_result["summary"]
            has_critical = scan_result["has_critical"]
            has_leak = scan_result["has_leak"]
            records = scan_result.get("records", [])

            # Collect credential previews (up to 10)
            preview_records = []
            has_raw_results = False
            file_download_info = None

            for rec in records:
                meta = (rec.metadata if hasattr(rec, 'metadata') else rec.get("metadata", {})) or {}
                email = meta.get("email", "")
                password = meta.get("password", "")
                if email and password:
                    preview_records.append({
                        "email": email,
                        "password": password[:60] + ("..." if len(password) > 60 else ""),
                    })
                    if len(preview_records) >= 10:
                        break

            raw_lines = []
            for i, rec in enumerate(records):
                content = rec.content if hasattr(rec, 'content') else rec.get("content", "")
                if content:
                    raw_lines.append(content[:200])
                    if len(raw_lines) >= 5:
                        break

            if not preview_records and raw_lines:
                has_raw_results = True

            total_count = len(records)

            result_preview = ""
            if not preview_records and raw_lines:
                result_preview = "\n\nResults:\n" + "\n".join(raw_lines)

            # Always generate a downloadable file when records exist
            if total_count > 0:
                ttm_file_path = None
                total_lines_in_file = 0
                for rec in records:
                    meta = (rec.metadata if hasattr(rec, 'metadata') else rec.get("metadata", {})) or {}
                    if meta.get("file_type") == "telegram_document" and meta.get("file_path"):
                        ttm_file_path = meta["file_path"]
                        total_lines_in_file = meta.get("total_lines", 0)
                        break

                if ttm_file_path and os.path.exists(ttm_file_path):
                    file_size_kb = os.path.getsize(ttm_file_path) // 1024
                    dl_name = f"ttm_{domain}.txt"
                    file_download_info = {
                        "fileName": dl_name,
                        "fileSizeMb": round(file_size_kb / 1024, 1),
                        "isLarge": file_size_kb > 500,
                        "download_url": f"/api/download?path={ttm_file_path}",
                        "total_lines": total_lines_in_file,
                    }
                else:
                    download_lines = []
                    for i, rec in enumerate(records):
                        content = rec.content if hasattr(rec, 'content') else rec.get("content", "")
                        meta = (rec.metadata if hasattr(rec, 'metadata') else rec.get("metadata", {})) or {}
                        download_lines.append(f"--- Record {i+1} ---")
                        download_lines.append(f"Source: {rec.source if hasattr(rec, 'source') else rec.get('source', '?')}")
                        download_lines.append(f"Type: {rec.record_type if hasattr(rec, 'record_type') else rec.get('record_type', '?')}")
                        download_lines.append(f"Content: {content}")
                        for f in os.listdir(os.path.join(SCRIPTS_DIR, "disma_data")):
                            pass  # placeholder
                        if meta.get("email") and meta.get("password"):
                            download_lines.append(f"Email: {meta['email']}")
                            download_lines.append(f"Password: {meta['password']}")
                        download_lines.append("")

                    dl_path = os.path.join(SCRIPTS_DIR, "disma_data", f"scan_{domain}_{int(time.time())}.txt")
                    os.makedirs(os.path.dirname(dl_path), exist_ok=True)
                    with open(dl_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(download_lines))

                    file_size_kb = os.path.getsize(dl_path) // 1024
                    file_download_info = {
                        "fileName": f"scan_{domain}.txt",
                        "fileSizeMb": round(file_size_kb / 1024, 1),
                        "isLarge": file_size_kb > 500,
                        "download_url": f"/api/download?path={dl_path}",
                    }

            dl_note = ""
            if file_download_info:
                size_mb = file_download_info['fileSizeMb']
                dl_note = f"\n\n\u2b07\ufe0f Download: {file_download_info['fileName']} ({size_mb} MB)\n   \u2192 {file_download_info['download_url']}"

            if has_critical:
                urgency = "CRITICAL"
            elif has_leak:
                urgency = "WARNING"
            else:
                urgency = "CLEAN"

            total_issues = scan_result.get("records_count", 0)
            cache_banner = f"\ud83d\udcc1 Cached scan results \u2014 say 'scan fresh {domain}' to re-scan.\n\n" if scan_result.get('from_cache') else ""

            if has_critical:
                final = cache_banner + f"\ud83d\udea8 CRITICAL: {total_issues} issue(s) on {domain}. Sensitive data exposed.{result_preview}{dl_note}"
            elif has_leak:
                final = cache_banner + f"\u26a0\ufe0f WARNING: {total_issues} issue(s) on {domain}. Suspicious activity found \u2014 review recommended.{result_preview}{dl_note}"
            else:
                final = cache_banner + f"\u2705 {domain} is clean. No issues found."

            threat_level = "low"
            status_text = "Clean"
            status_state = ""
            if has_critical:
                threat_level = "high"
                status_text = "Critical"
                status_state = "error"
            elif has_leak:
                threat_level = "medium"
                status_text = "Warning"
                status_state = ""

            # Generate MITRE mapping report
            mitre_report = None
            if total_count > 0:
                try:
                    # Convert records to dicts for MITRE mapper
                    finding_dicts = []
                    for rec in records[:50]:  # Limit to 50 for performance
                        finding_dicts.append({
                            "record_type": rec.record_type if hasattr(rec, 'record_type') else rec.get("record_type", "credential_leak"),
                            "severity": rec.severity if hasattr(rec, 'severity') else rec.get("severity", "info"),
                            "domain": domain,
                        })
                    mitre_report = generate_mitre_report(domain, finding_dicts)
                except Exception as e:
                    logger.warning(f"MITRE mapping failed: {e}")

            response_data = {
                "status": "ok",
                "response": final,
                "is_scan_result": True,
                "threat_level": threat_level,
                "target": domain,
                "status_text": status_text,
                "status_state": status_state,
            }

            if mitre_report:
                response_data["mitre"] = mitre_report.get("mitre")

            if preview_records or has_raw_results or total_count > 0:
                response_data["preview_records"] = preview_records
                response_data["total_records_count"] = total_count
                if file_download_info:
                    response_data["file_download"] = file_download_info
                    response_data["has_file_attachment"] = True

            with SESSIONS_LOCK:
                SESSIONS[session_id].append({"role": "assistant", "content": final})
            self._json(response_data)
            return

        # ── Non-scan: pure AI chat ──
        ai_reply = call_ai(ai_messages, max_tokens=350, system_prompt=SYSTEM_PROMPT)
        with SESSIONS_LOCK:
            SESSIONS[session_id].append({"role": "assistant", "content": ai_reply})
        self._json({
            "status": "ok",
            "response": ai_reply,
            "is_scan_result": False,
            "threat_level": "low",
            "status_text": "Clear",
        })


class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    status = '\u2014 Ready' if AI_TOKEN else '\u2014 NO TOKEN'
    print(f"[+] AI model: {AI_MODEL} {status}")
    print(f"[+] DISCOPE sources: {len([s for s in ENGINE.registry.get_enabled()])} enabled")
    print()
    print("=" * 60)
    print("  DISCOPE \u2014 Agent Server")
    print("=" * 60)
    print(f"  URL:      http://localhost:{PORT}")
    print(f"  AI Model: {AI_MODEL}")
    print(f"  Sources:  {len([s for s in ENGINE.registry.get_enabled()])} plugins active")
    print("=" * 60)
    print("  Open the URL and chat naturally.")
    print("=" * 60)
    print()

    server = ThreadedHTTPServer(("0.0.0.0", PORT), Handler)
    server._scanning = False
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down.")


if __name__ == "__main__":
    # CLI: python agent_server.py 8080
    port_arg = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].isdigit() else PORT
    PORT = int(port_arg)
    main()
