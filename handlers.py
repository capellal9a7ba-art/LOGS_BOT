# c:\Users\MARCOS\Desktop\LOGS BOT\handlers.py
import re
import uuid
import shutil
import asyncio
import zipfile
from pathlib import Path
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, FSInputFile
from aiogram.filters import CommandStart, Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import StatesGroup, State
from aiogram.exceptions import TelegramBadRequest

from config import DOWNLOAD_DIR, SESSIONS_DIR, OUTPUT_DIR, SESSION_TTL_SECONDS
from keyboards import main_menu_keyboard, session_action_keyboard
from downloader import download_from_url, parse_credentials_from_text
from cleanup import touch_session
from extractor import (
    unpack_archive,
    scan_session_stats,
    search_keywords_in_logs,
    collect_cookies,
    collect_cards,
    collect_all_passwords,
    package_tdata,
    package_rdp
)

router = Router()

URL_REGEX = re.compile(r"https?://\S+")

class BotState(StatesGroup):
    waiting_for_keyword = State()

def get_user_session_dir(user_id: int) -> Path:
    return SESSIONS_DIR / str(user_id)

async def send_file_safely(message: Message, file_path: Path, caption: str, filename_override: str = None):
    """
    Safely delivers files to user, auto-compressing to zip if > 30MB
    to ensure it complies with Telegram 50MB upload limits.
    """
    file_size = file_path.stat().st_size
    delivery_file = file_path
    temp_zip = None

    if file_size > 30 * 1024 * 1024 and file_path.suffix != ".zip":
        temp_zip = file_path.with_suffix(".zip")
        with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(file_path, arcname=file_path.name)
        delivery_file = temp_zip
        caption += " <i>(Compressed to ZIP)</i>"

    try:
        await message.answer_document(
            document=FSInputFile(str(delivery_file), filename=filename_override or delivery_file.name),
            caption=caption,
            parse_mode="HTML"
        )
    finally:
        if temp_zip and temp_zip.exists():
            temp_zip.unlink(missing_ok=True)
        if file_path.exists():
            file_path.unlink(missing_ok=True)

@router.message(CommandStart())
async def start_handler(message: Message, state: FSMContext):
    await state.clear()
    text = (
        "👋 <b>Welcome to Logs Extractor & Search Engine!</b>\n\n"
        "⚡ Send me a <code>.rar</code>, <code>.zip</code>, or <code>.7z</code> log archive (up to 6GB),\n"
        "or paste a download link (GoFile, Pixeldrain, MediaFire, Direct URL).\n\n"
        "<b>Available Operations:</b>\n"
        "🔍 <b>Keyword / Domain Search:</b> Instant combo extraction (e.g. <code>epicgames.com</code>, <code>netflix</code>)\n"
        "🍪 <b>Cookies Extractor:</b> Exports Netscape/TXT cookies in one file\n"
        "💳 <b>Cards & Autofill:</b> Scrapes payment cards and billing info\n"
        "🔑 <b>Full Combos:</b> Merges all credentials and login files\n"
        "✈️ <b>TData Sessions:</b> Packages Telegram desktop sessions\n"
        "🖥️ <b>RDP Profiles:</b> Gathers remote desktop configurations\n\n"
        "┌─────────────────────────────\n"
        "│ 🟢 ONLINE   ⚡ HIGH-SPEED\n"
        "└─────────────────────────────"
    )
    await message.answer(text, reply_markup=main_menu_keyboard(), parse_mode="HTML")

@router.callback_query(F.data == "how_to_use")
async def how_to_use_callback(query: CallbackQuery):
    guide = (
        "<b>📖 How to Use</b>\n\n"
        "1. <b>Send a file or link:</b>\n"
        "   - Upload <code>.rar</code>, <code>.zip</code>, or <code>.7z</code> (< 20MB via Telegram).\n"
        "   - Or paste a link from GoFile, Pixeldrain, or MediaFire (up to 6GB).\n"
        "2. <b>Password:</b> If the archive has a password, include it in your text (e.g. <code>pass: 1234</code>).\n"
        "3. <b>Actions:</b> Once unpacked, tap any action button.\n"
        "4. <b>Cleanup:</b> Click <b>Delete Session</b> when finished to clear disk."
    )
    await query.message.answer(guide, parse_mode="HTML")
    await query.answer()

@router.callback_query(F.data == "status_check")
async def status_check_callback(query: CallbackQuery):
    await query.answer("Bot is online, workers idle, 7z engine ready!", show_alert=True)

async def setup_session_archive(message: Message, archive_file: Path, password: str = None):
    user_id = message.from_user.id
    session_dir = get_user_session_dir(user_id)

    if session_dir.exists():
        shutil.rmtree(session_dir, ignore_errors=True)
    session_dir.mkdir(parents=True, exist_ok=True)

    status_msg = await message.answer(f"⏳ <b>Unpacking archive:</b> <code>{archive_file.name}</code>...", parse_mode="HTML")

    loop = asyncio.get_running_loop()
    success = await loop.run_in_executor(None, unpack_archive, archive_file, session_dir, password)

    if archive_file.exists():
        archive_file.unlink(missing_ok=True)

    if not success:
        await status_msg.edit_text(
            "❌ <b>Extraction Failed!</b>\n"
            "Ensure the archive is not corrupted, or provide the password if encrypted (e.g. <code>pass: yourpassword</code>).",
            parse_mode="HTML"
        )
        shutil.rmtree(session_dir, ignore_errors=True)
        return

    stats = await loop.run_in_executor(None, scan_session_stats, session_dir)
    await status_msg.delete()

    info_text = (
        f"✅ <b>Archive Loaded Successfully!</b>\n\n"
        f"📁 <b>Total Files:</b> <code>{stats['total_files']}</code>\n"
        f"🔑 <b>Password Logs:</b> <code>{stats['password_files']}</code>\n"
        f"🍪 <b>Cookie Files:</b> <code>{stats['cookie_files']}</code>\n"
        f"💳 <b>Card Files:</b> <code>{stats['card_files']}</code>\n"
        f"✈️ <b>TData Sessions:</b> <code>{stats['tdata_folders']}</code>\n"
        f"🖥️ <b>RDP Profiles:</b> <code>{stats['rdp_files']}</code>\n"
        f"📦 <b>Unpacked Size:</b> <code>{stats['size_mb']} MB</code>\n\n"
        f"⏱️ <i>Auto-Cleanup: This session will be purged from disk in {SESSION_TTL_SECONDS // 60} minutes to keep RAM & Disk free!</i>\n\n"
        f"🎯 <i>Select what you want to extract:</i>"
    )
    await message.answer(info_text, reply_markup=session_action_keyboard(), parse_mode="HTML")

@router.message(F.document)
async def document_upload_handler(message: Message, state: FSMContext):
    await state.clear()
    doc = message.document
    filename = doc.file_name or "archive.rar"
    suffix = Path(filename).suffix.lower()

    if suffix not in [".zip", ".rar", ".7z"]:
        await message.answer("⚠️ Supported formats: <code>.zip</code>, <code>.rar</code>, <code>.7z</code>", parse_mode="HTML")
        return

    if doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await message.answer(
            "⚠️ <b>Telegram 20MB Direct Upload Limit:</b>\n\n"
            "Telegram prevents bots from downloading files > 20MB directly.\n"
            "For large archives (up to 6GB), please upload to:\n"
            "• <a href='https://gofile.io'>GoFile.io</a>\n"
            "• <a href='https://pixeldrain.com'>Pixeldrain.com</a>\n"
            "• <a href='https://mediafire.com'>MediaFire</a>\n\n"
            "Then simply paste the link here!",
            parse_mode="HTML",
            disable_web_page_preview=True
        )
        return

    status_msg = await message.answer("📥 <b>Downloading archive...</b>", parse_mode="HTML")
    file_path = DOWNLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{filename}"

    try:
        bot = message.bot
        file_info = await bot.get_file(doc.file_id)
        await bot.download_file(file_info.file_path, destination=file_path)
        await status_msg.delete()
    except Exception as e:
        await status_msg.edit_text(f"❌ Download failed: {str(e)}")
        return

    password = parse_credentials_from_text(message.caption or "")
    await setup_session_archive(message, file_path, password=password)

@router.message(F.text, StateFilter(None))
async def text_link_handler(message: Message, state: FSMContext):
    text = message.text.strip()
    match = URL_REGEX.search(text)
    if not match:
        return

    url = match.group(0)
    password = parse_credentials_from_text(text)
    status_msg = await message.answer(f"🔗 <b>Fetching link:</b> <code>{url}</code>...", parse_mode="HTML")

    try:
        downloaded_file = await download_from_url(url)
        await status_msg.delete()
        await setup_session_archive(message, downloaded_file, password=password)
    except Exception as e:
        await status_msg.edit_text(f"❌ <b>Download Error:</b> <code>{str(e)}</code>", parse_mode="HTML")

@router.callback_query(F.data == "action_search")
async def action_search_callback(query: CallbackQuery, state: FSMContext):
    session_dir = get_user_session_dir(query.from_user.id)
    if not session_dir.exists():
        await query.answer("⚠️ No active archive loaded.", show_alert=True)
        return

    await state.set_state(BotState.waiting_for_keyword)
    await query.message.answer(
        "🔍 <b>Keyword / Domain Search:</b>\n\n"
        "Send the service or domain name you want to extract:\n"
        "<i>Examples:</i> <code>epicgames.com</code>, <code>netflix</code>, <code>steam</code>, <code>roblox</code>",
        parse_mode="HTML"
    )
    await query.answer()

@router.message(BotState.waiting_for_keyword)
async def process_keyword_search(message: Message, state: FSMContext):
    keyword = message.text.strip()
    if not keyword:
        await message.answer("Please send a valid keyword.")
        return

    await state.clear()
    session_dir = get_user_session_dir(message.from_user.id)
    if not session_dir.exists():
        await message.answer("⚠️ Session expired. Please re-send the archive.")
        return

    status_msg = await message.answer(f"🔎 <b>Searching credentials for:</b> <code>{keyword}</code>...", parse_mode="HTML")

    loop = asyncio.get_running_loop()
    matches, total_found = await loop.run_in_executor(None, search_keywords_in_logs, session_dir, keyword)

    if total_found == 0:
        await status_msg.edit_text(f"❌ No matches found for <code>{keyword}</code>.", parse_mode="HTML")
        await message.answer("Select another action:", reply_markup=session_action_keyboard())
        return

    out_file = OUTPUT_DIR / f"search_{message.from_user.id}_{keyword[:15]}.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"# Target: {keyword} | Total Found: {total_found}\n")
        f.write("#" + "=" * 50 + "\n\n")
        for m in matches:
            f.write(m + "\n")

    await status_msg.delete()
    await send_file_safely(
        message=message,
        file_path=out_file,
        caption=f"🎯 <b>Found {total_found} entries for:</b> <code>{keyword}</code>",
        filename_override=f"results_{keyword}.txt"
    )
    await message.answer("Select another action:", reply_markup=session_action_keyboard())

@router.callback_query(F.data == "action_cookies")
async def action_cookies_callback(query: CallbackQuery):
    session_dir = get_user_session_dir(query.from_user.id)
    if not session_dir.exists():
        await query.answer("⚠️ No active archive loaded.", show_alert=True)
        return

    status_msg = await query.message.answer("🍪 <b>Aggregating cookies across all logs...</b>", parse_mode="HTML")
    out_file = OUTPUT_DIR / f"cookies_{query.from_user.id}.txt"

    loop = asyncio.get_running_loop()
    file_count, total_lines = await loop.run_in_executor(None, collect_cookies, session_dir, out_file)

    if file_count == 0 or total_lines == 0:
        await status_msg.edit_text("⚠️ No cookie records found in this archive.")
        out_file.unlink(missing_ok=True)
        await query.answer()
        return

    await status_msg.delete()
    await send_file_safely(
        message=query.message,
        file_path=out_file,
        caption=f"🍪 <b>Collected {total_lines:,} cookie lines from {file_count} log sources!</b>",
        filename_override="all_cookies.txt"
    )
    await query.answer()

@router.callback_query(F.data == "action_cards")
async def action_cards_callback(query: CallbackQuery):
    session_dir = get_user_session_dir(query.from_user.id)
    if not session_dir.exists():
        await query.answer("⚠️ No active archive loaded.", show_alert=True)
        return

    status_msg = await query.message.answer("💳 <b>Deep scanning for credit cards & autofill...</b>", parse_mode="HTML")
    out_file = OUTPUT_DIR / f"cards_{query.from_user.id}.txt"

    loop = asyncio.get_running_loop()
    total_cards, files_with_cards = await loop.run_in_executor(None, collect_cards, session_dir, out_file)

    if total_cards == 0:
        await status_msg.edit_text("⚠️ No credit card or autofill records found.")
        out_file.unlink(missing_ok=True)
        await query.answer()
        return

    await status_msg.delete()
    await send_file_safely(
        message=query.message,
        file_path=out_file,
        caption=f"💳 <b>Extracted {total_cards:,} unique credit cards from {files_with_cards} files!</b>",
        filename_override="cards_autofill.txt"
    )
    await query.answer()

@router.callback_query(F.data == "action_passwords")
async def action_passwords_callback(query: CallbackQuery):
    session_dir = get_user_session_dir(query.from_user.id)
    if not session_dir.exists():
        await query.answer("⚠️ No active archive loaded.", show_alert=True)
        return

    status_msg = await query.message.answer("🔑 <b>Compiling passwords & combos...</b>", parse_mode="HTML")
    out_file = OUTPUT_DIR / f"all_passwords_{query.from_user.id}.txt"

    loop = asyncio.get_running_loop()
    count = await loop.run_in_executor(None, collect_all_passwords, session_dir, out_file)

    if count == 0:
        await status_msg.edit_text("⚠️ No password logs found.")
        out_file.unlink(missing_ok=True)
        await query.answer()
        return

    await status_msg.delete()
    await send_file_safely(
        message=query.message,
        file_path=out_file,
        caption=f"🔑 <b>Compiled from {count} password files!</b>",
        filename_override="all_passwords.txt"
    )
    await query.answer()

@router.callback_query(F.data == "action_tdata")
async def action_tdata_callback(query: CallbackQuery):
    session_dir = get_user_session_dir(query.from_user.id)
    if not session_dir.exists():
        await query.answer("⚠️ No active archive loaded.", show_alert=True)
        return

    status_msg = await query.message.answer("✈️ <b>Packaging TData sessions...</b>", parse_mode="HTML")
    out_zip = OUTPUT_DIR / f"tdata_{query.from_user.id}.zip"

    loop = asyncio.get_running_loop()
    count = await loop.run_in_executor(None, package_tdata, session_dir, out_zip)

    if count == 0:
        await status_msg.edit_text("⚠️ No TData folders found.")
        out_zip.unlink(missing_ok=True)
        await query.answer()
        return

    await status_msg.delete()
    await send_file_safely(
        message=query.message,
        file_path=out_zip,
        caption=f"✈️ <b>Extracted {count} TData session folders!</b>",
        filename_override="tdata_sessions.zip"
    )
    await query.answer()

@router.callback_query(F.data == "action_rdp")
async def action_rdp_callback(query: CallbackQuery):
    session_dir = get_user_session_dir(query.from_user.id)
    if not session_dir.exists():
        await query.answer("⚠️ No active archive loaded.", show_alert=True)
        return

    status_msg = await query.message.answer("🖥️ <b>Packaging RDP profiles...</b>", parse_mode="HTML")
    out_zip = OUTPUT_DIR / f"rdp_{query.from_user.id}.zip"

    loop = asyncio.get_running_loop()
    count = await loop.run_in_executor(None, package_rdp, session_dir, out_zip)

    if count == 0:
        await status_msg.edit_text("⚠️ No RDP profiles found.")
        out_zip.unlink(missing_ok=True)
        await query.answer()
        return

    await status_msg.delete()
    await send_file_safely(
        message=query.message,
        file_path=out_zip,
        caption=f"🖥️ <b>Extracted {count} RDP profiles!</b>",
        filename_override="rdp_profiles.zip"
    )
    await query.answer()

@router.callback_query(F.data == "action_stats")
async def action_stats_callback(query: CallbackQuery):
    session_dir = get_user_session_dir(query.from_user.id)
    if not session_dir.exists():
        await query.answer("⚠️ No active archive loaded.", show_alert=True)
        return

    loop = asyncio.get_running_loop()
    stats = await loop.run_in_executor(None, scan_session_stats, session_dir)
    text = (
        f"📊 <b>Detailed Archive Stats:</b>\n\n"
        f"📁 Total Files: <code>{stats['total_files']}</code>\n"
        f"🔑 Password Files: <code>{stats['password_files']}</code>\n"
        f"🍪 Cookie Files: <code>{stats['cookie_files']}</code>\n"
        f"💳 Card Files: <code>{stats['card_files']}</code>\n"
        f"✈️ TData Sessions: <code>{stats['tdata_folders']}</code>\n"
        f"🖥️ RDP Profiles: <code>{stats['rdp_files']}</code>\n"
        f"💾 Working Size: <code>{stats['size_mb']} MB</code>"
    )
    await query.message.answer(text, parse_mode="HTML")
    await query.answer()

@router.callback_query(F.data == "action_clear")
async def action_clear_callback(query: CallbackQuery, state: FSMContext):
    await state.clear()
    session_dir = get_user_session_dir(query.from_user.id)
    if session_dir.exists():
        shutil.rmtree(session_dir, ignore_errors=True)
    await query.message.edit_text("🗑️ <b>Session wiped and disk freed!</b>\n\nReady for your next archive or link.", parse_mode="HTML")
    await query.answer()
