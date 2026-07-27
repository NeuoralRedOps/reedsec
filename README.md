# DISCOPE — Stealer Log Analysis Chatbot (SLAC)

AI-powered threat intelligence chatbot that scans domains for stealer logs and credential leaks across multiple OSINT sources, with semantic search over indexed data.

## Features

- **Multi-source scanning** — Pastebin, CRT.sh, Ahmia, Telegram, TTM Logs Bot, custom APIs
- **Semantic search (RAG)** — Ask natural-language questions about indexed credentials using local vector embeddings
- **Real AI chat** — Nous Research API with 3-tier guardrail system (social / casual / off-topic)
- **Premium dark UI** — Linear/Notion-style minimal interface
- **Telegram MTProto ingestion** — Automated retrieval from stealer log bots via Telethon
- **Pluggable architecture** — Drop-in data source connectors, auto-discovered
- **Session memory** — Server-side conversation history per session

## Quick Start

```bash
# 1. Install dependencies
pip install sentence-transformers telethon

# 2. Set credentials (never commit these)
export TG_API_ID="your_telegram_api_id"
export TG_API_HASH="your_telegram_api_hash"
export TG_PHONE="your_phone_number"
export OPENROUTER_API_KEY="your_openrouter_key"
export NOUS_API_KEY="your_nous_api_key"  # or use ~/AppData/Local/hermes/auth.json

# 3. Run
python agent_server.py --port 8080
```

**Required env vars for full functionality:**
- `TG_API_ID` + `TG_API_HASH` — Telegram bridge (stealer log downloads)
- `OPENROUTER_API_KEY` — Primary AI models (MiMo V2.5, DeepSeek V4, Nemotron 3)
- `NOUS_API_KEY` — Fallback AI models (or use auth.json)

Open **http://localhost:8080** in your browser.

## Architecture

```
agent_server.py          → HTTP server + chat UI + API endpoints
chat_ui_new.html         → Frontend (Linear/Notion dark theme)
disma_core/
  engine.py              → Orchestrator — manages sources, storage, scans
  database.py            → SQLite + FTS5 storage engine
  semantic.py            → Vector embeddings + RAG retrieval (all-MiniLM-L6-v2)
  base_source.py         → Abstract plugin interface + Registry
  sources/               → Pluggable data source connectors
    pastebin_source.py
    crtsh_source.py
    ahmia_source.py
    telegram_source.py
    ttmlogs_source.py    → @TTMlogsBot via Telethon subprocess bridge
    custom_api_source.py
    webhook_source.py
telegram_bridge.py       → Telethon user-bridge for DM-only bots
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Chat UI |
| `/api/health` | GET | Health check + stats |
| `/api/chat` | POST | Chat (scan + RAG + conversation) |
| `/api/semantic/query` | POST | Direct RAG query with sources |
| `/api/sources` | GET | List data sources + record counts |
| `/api/documents` | GET | List indexed documents |
| `/api/history` | GET | Query history |
| `/api/stats` | GET | Full system stats |
| `/api/download` | GET | Download scan result files |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TG_API_ID` | Telegram API ID from my.telegram.org |
| `TG_API_HASH` | Telegram API hash |
| `TG_PHONE` | Phone number for Telegram login |
| `NOUS_API_KEY` | Nous Research API key (or use auth.json) |

## Versioning

- **main** — stable, tested code
- **dev** — active development (merge to main when stable)
- Tags: `v0.1.0`, `v0.2.0`, etc. for releases
