#!/usr/bin/env python3
"""QR code login for Telegram — scan with your phone, no codes needed."""
import asyncio, os, sys

API_ID = int(os.environ.get("TG_API_ID", "0"))
API_HASH = os.environ.get("TG_API_HASH", "")

SESSIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "disma_data", "tg_sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

async def main():
    from telethon import TelegramClient
    
    session_file = os.path.join(SESSIONS_DIR, "ttm_user")
    client = TelegramClient(session_file, API_ID, API_HASH)
    await client.connect()

    if await client.is_user_authorized():
        me = await client.get_me()
        print(f"[OK] Already logged in as {me.username or me.first_name}")
        await client.disconnect()
        return

    try:
        # QR login
        qr_login = await client.qr_login()
        
        import qrcode
        qr = qrcode.QRCode(border=2, box_size=10)
        qr.add_data(qr_login.url)
        qr.make(fit=True)

        # Save PNG image
        img_path = os.path.join(SESSIONS_DIR, "tg_qr_login.png")
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(img_path)

        print(f"\n{'='*50}")
        print(f"  TELEGRAM QR LOGIN")
        print(f"{'='*50}")
        print(f"  1. Open Telegram on your phone")
        print(f"  2. Go to Settings → Devices → Scan QR")
        print(f"  3. Scan the image at: {img_path}")
        print(f"  4. Or open this URL on your phone:")
        print(f"     {qr_login.url}")
        print(f"{'='*50}\n")
        print(f"MEDIA:{img_path}")
        sys.stdout.flush()

        # Wait for login (120s timeout)
        await qr_login.wait(timeout=120)
        me = await client.get_me()
        print(f"[OK] ✓ Logged in as {me.username or me.first_name}")

    except asyncio.TimeoutError:
        print("[ERROR] QR code expired. Restart the script to get a new one.")
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
    finally:
        if client.is_connected():
            await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
