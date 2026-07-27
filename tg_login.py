#!/usr/bin/env python3
"""Telegram login — ONE STEP: sends code and verifies in single run.
Usage: python tg_login.py <code>
"""
import asyncio, os, sys

SESSIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "disma_data", "tg_sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

API_ID = int(os.environ.get("TG_API_ID", "0"))
API_HASH = os.environ.get("TG_API_HASH", "")
PHONE = os.environ.get("TG_PHONE", "")

async def main():
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.errors import PhoneCodeInvalidError, PhoneCodeExpiredError

    code = sys.argv[1] if len(sys.argv) > 1 else ""
    if not code:
        print("Usage: tg_login.py <code>")
        sys.exit(1)

    client = TelegramClient(StringSession(), API_ID, API_HASH)
    await client.connect()

    # Send code request
    result = await client.send_code_request(PHONE)
    phone_code_hash = result.phone_code_hash

    # Immediately verify
    try:
        await client.sign_in(phone=PHONE, code=code, phone_code_hash=phone_code_hash)
    except PhoneCodeInvalidError:
        print("INVALID_CODE")
        sys.exit(1)
    except PhoneCodeExpiredError:
        print("CODE_EXPIRED")
        sys.exit(1)
    except Exception as e:
        if "password" in str(e).lower():
            print("2FA_REQUIRED")
        else:
            print(f"ERROR: {e}")
        sys.exit(1)

    me = await client.get_me()
    print(f"OK:{me.first_name}")

    # Save session string
    saved = client.session.save()
    auth_file = os.path.join(SESSIONS_DIR, "ttm_saved_auth.txt")
    with open(auth_file, "w") as f:
        f.write(saved)
    print("SAVED")
    await client.disconnect()

asyncio.run(main())
