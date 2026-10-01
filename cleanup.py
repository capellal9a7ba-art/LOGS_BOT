# c:\Users\MARCOS\Desktop\LOGS BOT\cleanup.py
import os
import time
import shutil
import asyncio
import logging
from pathlib import Path
from config import USERS_SESSIONS_DIR, DOWNLOAD_DIR, OUTPUT_DIR, SESSION_TTL_SECONDS

logger = logging.getLogger("cleanup_worker")

def purge_expired_items(directory: Path, ttl_seconds: int = SESSION_TTL_SECONDS) -> int:
    """Scans a directory and deletes files/folders older than ttl_seconds."""
    now = time.time()
    deleted_count = 0

    if not directory.exists():
        return 0

    for item in directory.iterdir():
        try:
            mtime = item.stat().st_mtime
            age = now - mtime
            if age > ttl_seconds:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                    logger.info(f"[*] Auto-removed expired folder: {item.name} (Age: {int(age)}s)")
                else:
                    item.unlink(missing_ok=True)
                    logger.info(f"[*] Auto-removed expired file: {item.name} (Age: {int(age)}s)")
                deleted_count += 1
        except Exception as e:
            logger.error(f"[!] Error deleting expired item {item}: {e}")

    return deleted_count

async def background_cleanup_loop(interval_seconds: int = 60):
    """Background task that runs continuously to guarantee free disk space on Railway."""
    logger.info(f"[*] Background disk cleanup worker started (TTL: {SESSION_TTL_SECONDS}s / {SESSION_TTL_SECONDS // 60}m).")
    while True:
        try:
            purge_expired_items(USERS_SESSIONS_DIR, SESSION_TTL_SECONDS)
            purge_expired_items(DOWNLOAD_DIR, SESSION_TTL_SECONDS)
            purge_expired_items(OUTPUT_DIR, SESSION_TTL_SECONDS)
        except Exception as err:
            logger.error(f"[!] Cleanup loop encountered error: {err}")
        await asyncio.sleep(interval_seconds)

def touch_session(session_path: Path):
    """Updates modification time to extend session while user actively interacts."""
    try:
        if session_path.exists():
            now = time.time()
            os.utime(session_path, (now, now))
    except Exception:
        pass
