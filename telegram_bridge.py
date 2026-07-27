#!/usr/bin/env python3
"""
Telegram User Bot Bridge — Talks to @TTMlogsBot as a USER.
Used by DISCOPE to query stealer logs via Telegram DM.

Handles the full conversational flow:
  /search domain  → bot offers format → bridge clicks inline button → bot sends ZIP file

Uses StringSession to avoid SQLite file locking on repeated invocations.

Install:  pip install telethon
"""
import asyncio
import json
import os
import sys
import zipfile
import io
import time

SESSIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "disma_data", "tg_sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

API_ID = os.environ.get("TG_API_ID", "0")
API_HASH = os.environ.get("TG_API_HASH", "")

SESSION_STRING_FILE = os.path.join(SESSIONS_DIR, "ttm_saved_auth.txt")
SESSION_TEMPLATE = os.path.join(SESSIONS_DIR, "ttm_session_base")
TARGET = "@TTMlogsBot"
MAX_WAIT = 50
POLL_INTERVAL = 3


async def get_latest(client, target, skip_texts=None):
    if skip_texts is None:
        skip_texts = []
    for _ in range(15):
        await asyncio.sleep(2)
        msgs = await client.get_messages(target, limit=5)
        for m in msgs:
            if m.out:
                continue
            if m.text and any(s == m.text.strip() for s in skip_texts):
                continue
            return m
    return None


async def wait_for_file(client, target, after_id):
    sys.stderr.write(f"DEBUG: wait_for_file after_id={after_id}\n")
    sys.stderr.flush()
    for i in range(int(MAX_WAIT / POLL_INTERVAL)):
        await asyncio.sleep(POLL_INTERVAL)
        msgs = await client.get_messages(target, limit=5)
        for m in msgs:
            if m.out or m.id <= after_id:
                continue
            if m.media:
                sys.stderr.write(f"DEBUG: found media msg id={m.id}\n")
                sys.stderr.flush()
                return m
        latest = await client.get_messages(target, limit=3)
        for m in latest:
            if m.out or m.id <= after_id:
                continue
            txt = (m.text or "").lower()
            if any(p in txt for p in ["no string", "no result", "❌", "started search"]):
                sys.stderr.write(f"DEBUG: found text '{txt[:50]}' id={m.id}\n")
                sys.stderr.flush()
                return m
            if m.text and not m.media:
                if not any(p in txt for p in ["choose", "format", "select"]):
                    sys.stderr.write(f"DEBUG: found other text '{txt[:50]}' id={m.id}\n")
                    sys.stderr.flush()
                    return m
    sys.stderr.write("DEBUG: wait_for_file timeout\n")
    sys.stderr.flush()
    return None


async def download_doc(m, label):
    raw_path = os.path.join(SESSIONS_DIR, f"ttm_raw_{label}_{m.id}.bin")
    await m.download_media(raw_path)
    file_size = os.path.getsize(raw_path)
    preview = []
    extracted_text = ""
    is_zip = False
    inner_name = ""
    with open(raw_path, "rb") as f:
        header = f.read(4)
        is_zip = header[:2] == b"PK"
    if is_zip:
        try:
            with zipfile.ZipFile(raw_path) as zf:
                names = zf.namelist()
                if names:
                    inner_name = names[0]
                    content_bytes = zf.read(names[0])
                    file_text = content_bytes.decode("utf-8", errors="replace")
                    extracted_text = file_text
        except Exception:
            with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
                extracted_text = f.read()
    else:
        with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
            extracted_text = f.read()
    lines = extracted_text.split("\n")
    total_lines = len(lines)
    preview = lines[:20]
    clean_name = f"ttm_{label}.txt"
    clean_path = os.path.join(SESSIONS_DIR, clean_name)
    with open(clean_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(extracted_text)
    return {
        "type": "document",
        "file_path": clean_path,
        "file_name": clean_name,
        "file_size": file_size,
        "total_lines": total_lines,
        "preview": preview,
        "is_zip": is_zip,
        "inner_name": inner_name,
        "extracted_text": extracted_text[:10000],
    }


async def handle_format_and_get_file(client, target, format_msg, label):
    if not format_msg.reply_markup:
        sys.stderr.write("DEBUG: no reply_markup\n")
        sys.stderr.flush()
        return None
    last_id = format_msg.id
    btn_clicked = False
    for row in format_msg.reply_markup.rows:
        for btn in row.buttons:
            bdata = getattr(btn, "data", None)
            try:
                await format_msg.click(data=bdata)
                btn_clicked = True
            except Exception:
                try:
                    await format_msg.click(text=btn.text)
                    btn_clicked = True
                except Exception:
                    continue
            break
        if btn_clicked:
            break
    if not btn_clicked:
        return None
    file_msg = await wait_for_file(client, target, last_id)
    if file_msg:
        if file_msg.media:
            return await download_doc(file_msg, label)
        if file_msg.text:
            return {"type": "text", "text": file_msg.text[:5000]}
        return {"error": "Empty response"}
    latest = await client.get_messages(target, limit=1)
    if latest and latest[0].text and not latest[0].out:
        return {"type": "text", "text": latest[0].text[:5000]}
    return {"error": "No response after format click"}


async def send_and_get_response(client, target, query, label):
    await client.send_message(target, query)
    m = await get_latest(client, target, skip_texts=[query.strip(), f"/{query.strip()}"])
    if not m:
        return {"error": "No response from @TTMlogsBot"}
    sys.stderr.write(f"DEBUG: got_msg type={type(m).__name__} has_media={bool(m.media)} has_markup={bool(m.reply_markup)}\n")
    sys.stderr.flush()
    if m.media:
        return await download_doc(m, label)
    if m.reply_markup:
        result = await handle_format_and_get_file(client, target, m, label)
        if result:
            return result
    if m.text:
        return {"type": "text", "text": m.text[:5000]}
    return {"error": "Unexpected empty response"}


async def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage:")
        print("  python telegram_bridge.py --phone          (start fresh, save session string)")
        print("  python telegram_bridge.py --search domain  (search by domain)")
        print("  python telegram_bridge.py --mail email     (search by email)")
        print("  python telegram_bridge.py --status         (check connection)")
        sys.exit(0)

    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        print('{"error": "telethon not installed. Run: pip install telethon"}')
        sys.exit(1)

    if API_ID == "0" or not API_HASH:
        print('{"error": "Set TG_API_ID and TG_API_HASH env vars"}')
        sys.exit(1)

    # Load saved session string, or start fresh with a unique SQLite session
    session_string = ""
    if os.path.exists(SESSION_STRING_FILE):
        with open(SESSION_STRING_FILE, "r") as f:
            session_string = f.read().strip()

    if session_string:
        session = StringSession(session_string)
    else:
        # Try the copied session first (avoids locked original)
        copied_path = os.path.join(SESSIONS_DIR, "ttm_copied.session")
        base_path = os.path.join(SESSIONS_DIR, "ttm_user.session")
        if os.path.exists(copied_path):
            session = copied_path
        elif os.path.exists(base_path):
            session = base_path
        else:
            # Use a unique session filename to avoid Windows file locking
            unique_name = f"{SESSION_TEMPLATE}_{int(time.time())}"
            session = unique_name

    client = TelegramClient(session, int(API_ID), API_HASH)

    try:
        await client.start()
    except Exception as e:
        if os.path.exists(SESSION_STRING_FILE):
            os.remove(SESSION_STRING_FILE)
        print(json.dumps({"error": f"Auth failed: {e}. Re-run with --phone"}))
        return

    # Save session string for next time (avoids file locking on Windows)
    if isinstance(session, StringSession) or not session_string:
        try:
            saved = session.save()
            with open(SESSION_STRING_FILE, "w") as f:
                f.write(saved)
        except Exception:
            pass

    if sys.argv[1] == "--phone":
        me = await client.get_me()
        print(json.dumps({"status": "logged_in", "phone": str(me.phone)}))
        return

    target = await client.get_entity(TARGET)

    if sys.argv[1] == "--status":
        result = await send_and_get_response(client, target, "/info", "info")
        print(json.dumps(result))
        return

    if sys.argv[1] == "--search" and len(sys.argv) > 2:
        domain = sys.argv[2]
        result = await send_and_get_response(client, target, f"/search {domain}", f"search_{domain}")
        print(json.dumps(result))
        return

    if sys.argv[1] == "--mail" and len(sys.argv) > 2:
        email = sys.argv[2]
        result = await send_and_get_response(client, target, f"/mail {email}", f"mail_{email}")
        print(json.dumps(result))
        return

    print(f'{{"error": "Unknown command: {" ".join(sys.argv[1:])}"}}')


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
