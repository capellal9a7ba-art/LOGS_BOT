# c:\Users\MARCOS\Desktop\LOGS BOT\bot.py
import asyncio
import logging
import sys
from aiogram import Bot, Dispatcher

from config import BOT_TOKEN
from handlers import router
from cleanup import background_cleanup_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

async def main():
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN_HERE":
        print("[!] ERROR: Set BOT_TOKEN in .env or Railway variables before running.")
        return

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)

    # Launch background auto-cleanup worker (purges files older than 5 minutes)
    cleanup_task = asyncio.create_task(background_cleanup_loop(interval_seconds=60))

    print("[*] Log Extraction & Search Bot started successfully.")
    print("[*] Auto-disk purge initialized: files deleted after 5 minutes of inactivity.")

    try:
        await dp.start_polling(bot)
    finally:
        cleanup_task.cancel()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Bot stopped gracefully.")
