# c:\Users\MARCOS\Desktop\LOGS BOT\downloader.py
import re
import os
import aiohttp
import aiofiles
from pathlib import Path
from typing import Optional, Callable, Awaitable, Tuple
from config import DOWNLOAD_DIR, MAX_ARCHIVE_SIZE_MB

GOFILE_REGEX = re.compile(r"https?://(?:www\.)?gofile\.io/d/([a-zA-Z0-9]+)")
PIXELDRAIN_REGEX = re.compile(r"https?://(?:www\.)?pixeldrain\.com/u/([a-zA-Z0-9]+)")
MEDIAFIRE_REGEX = re.compile(r"https?://(?:www\.)?mediafire\.com/file/([a-zA-Z0-9]+)")
DROPBOX_REGEX = re.compile(r"https?://(?:www\.)?dropbox\.com/s(?:h)?/([a-zA-Z0-9]+)")

async def resolve_gofile_link(session: aiohttp.ClientSession, content_id: str) -> Optional[Tuple[str, str]]:
    """Resolves a GoFile share link to direct download link and filename."""
    token_url = "https://api.gofile.io/accounts"
    try:
        async with session.post(token_url) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            token = data.get("data", {}).get("token")
            if not token:
                return None

        headers = {"Authorization": f"Bearer {token}"}
        content_url = f"https://api.gofile.io/contents/{content_id}?wt=4fd6sg89d7s6"
        async with session.get(content_url, headers=headers) as resp:
            if resp.status != 200:
                return None
            cdata = await resp.json()
            children = cdata.get("data", {}).get("children", {})
            if not children:
                return None
            first_child = next(iter(children.values()))
            direct_link = first_child.get("link")
            name = first_child.get("name", f"gofile_{content_id}.zip")
            return direct_link, name
    except Exception:
        return None

def resolve_pixeldrain_link(file_id: str) -> Tuple[str, str]:
    """Resolves Pixeldrain file link to direct API endpoint."""
    return f"https://pixeldrain.com/api/file/{file_id}", f"pixeldrain_{file_id}.zip"

async def resolve_mediafire_link(session: aiohttp.ClientSession, url: str) -> Optional[Tuple[str, str]]:
    """Scrapes Mediafire direct download link."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        async with session.get(url, headers=headers) as resp:
            if resp.status != 200:
                return None
            html = await resp.text()
            match = re.search(r'aria-label="Download file"\s+href="([^"]+)"', html)
            if not match:
                match = re.search(r'href="((?:https?:)?//download\d+\.mediafire\.com/[^"]+)"', html)
            if match:
                direct = match.group(1)
                name_match = re.search(r'class="filename">([^<]+)<', html)
                name = name_match.group(1).strip() if name_match else "mediafire_download.zip"
                return direct, name
    except Exception:
        pass
    return None

def parse_credentials_from_text(text: str) -> Optional[str]:
    """Extracts password if sent alongside a link (e.g. 'pass: 1234' or 'password: secret')."""
    patterns = [
        r"(?:password|pass|pwd)[:= ]+([^\s\n]+)",
        r"(?:ключ|пароль)[:= ]+([^\s\n]+)"
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None

async def download_from_url(
    url: str,
    target_dir: Path = DOWNLOAD_DIR,
    progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None
) -> Path:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    timeout = aiohttp.ClientTimeout(total=None, sock_read=1800, connect=120)
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        direct_url = url.strip()
        filename = None

        gf_match = GOFILE_REGEX.search(direct_url)
        px_match = PIXELDRAIN_REGEX.search(direct_url)
        mf_match = MEDIAFIRE_REGEX.search(direct_url)

        if gf_match:
            res = await resolve_gofile_link(session, gf_match.group(1))
            if res:
                direct_url, filename = res
        elif px_match:
            direct_url, filename = resolve_pixeldrain_link(px_match.group(1))
        elif mf_match:
            res = await resolve_mediafire_link(session, direct_url)
            if res:
                direct_url, filename = res
        elif "dropbox.com" in direct_url:
            direct_url = direct_url.replace("?dl=0", "?dl=1")
            if "?dl=1" not in direct_url:
                direct_url += "?dl=1"

        async with session.get(direct_url, allow_redirects=True) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP error {response.status} while fetching file")

            total_size = int(response.headers.get("Content-Length", 0))
            if total_size > MAX_ARCHIVE_SIZE_MB * 1024 * 1024:
                raise ValueError(f"File size exceeds limit ({MAX_ARCHIVE_SIZE_MB}MB)")

            if not filename:
                cdisp = response.headers.get("Content-Disposition", "")
                if "filename=" in cdisp:
                    filename = cdisp.split("filename=")[-1].strip('"\'; ')
                else:
                    path_name = Path(direct_url.split("?")[0]).name
                    filename = path_name if path_name else "archive.zip"

            save_path = target_dir / filename
            downloaded = 0
            chunk_size = 2 * 1024 * 1024 # 2MB chunks for maximum throughput

            async with aiofiles.open(save_path, "wb") as f:
                async for chunk in response.content.iter_chunked(chunk_size):
                    await f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total_size > 0:
                        await progress_callback(downloaded, total_size)

            return save_path
