# c:\Users\MARCOS\Desktop\LOGS BOT\config.py
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
MAX_ARCHIVE_SIZE_MB = int(os.getenv("MAX_ARCHIVE_SIZE_MB", "6144")) # 6GB support for Railway
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "300")) # 5 Minutes auto-cleanup

DOWNLOAD_DIR = BASE_DIR / os.getenv("DOWNLOAD_DIR", "downloads")
SESSIONS_DIR = BASE_DIR / os.getenv("SESSIONS_DIR", "sessions")
OUTPUT_DIR = BASE_DIR / os.getenv("OUTPUT_DIR", "extracted_outputs")

DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
