# c:\Users\MARCOS\Desktop\LOGS BOT\extractor.py
import os
import shutil
import zipfile
import subprocess
import re
import sqlite3
from pathlib import Path
from typing import List, Set, Optional, Tuple, Dict

try:
    import py7zr
except ImportError:
    py7zr = None

try:
    import rarfile
except ImportError:
    rarfile = None

PASSWORD_FILENAMES = {
    "passwords.txt", "password.txt", "passwords", "credentials.txt",
    "logins.txt", "all passwords.txt", "account.txt", "accounts.txt"
}

# Ignore extensions that definitely never contain text/credentials
NON_CRED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".mp3", ".mp4", ".avi", ".mkv", ".wav",
    ".exe", ".dll", ".sys", ".so", ".dylib",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".pdf", ".docx", ".xlsx", ".pptx"
}

def find_system_7z() -> Optional[str]:
    """Finds system 7z binary if available."""
    for binary in ["7z", "7za", "7zr", "C:\\Program Files\\7-Zip\\7z.exe"]:
        found = shutil.which(binary)
        if found:
            return found
        if os.path.isfile(binary):
            return binary
    return None

def unpack_archive(archive_path: Path, dest_dir: Path, password: Optional[str] = None) -> bool:
    """
    Unpacks ZIP, RAR, or 7Z archives completely into dest_dir.
    Prioritizes native 7z CLI for maximum speed and RAR5 compatibility.
    Falls back to Python libraries.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    suffix = archive_path.suffix.lower()
    seven_z = find_system_7z()

    # Strategy 1: System 7z CLI
    if seven_z:
        cmd = [seven_z, "x", str(archive_path), f"-o{dest_dir}", "-y"]
        if password:
            cmd.append(f"-p{password}")
        else:
            cmd.append("-p-")
        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
            if res.returncode == 0 and any(dest_dir.iterdir()):
                return True
        except Exception as e:
            print(f"[!] 7z CLI execution failed: {e}")

    # Strategy 2: Python Libraries Fallback
    pwd_bytes = password.encode() if password else None
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as z:
                for member in z.infolist():
                    target_path = dest_dir / member.filename
                    if not target_path.resolve().is_relative_to(dest_dir.resolve()):
                        continue
                    z.extract(member, path=dest_dir, pwd=pwd_bytes)
            return True

        elif suffix == ".rar" and rarfile:
            with rarfile.RarFile(archive_path, "r") as r:
                if password:
                    r.setpassword(password)
                r.extractall(path=dest_dir)
            return True

        elif suffix == ".7z" and py7zr:
            with py7zr.SevenZipFile(archive_path, mode="r", password=password) as z:
                z.extractall(path=dest_dir)
            return True

    except Exception as err:
        print(f"[!] Python extraction failed: {err}")

    return False

def is_cookie_path(root_lower: str, file_lower: str) -> bool:
    """Checks if a file is a cookie file by parent directory or filename."""
    if "cookie" in root_lower or "cookie" in file_lower:
        return file_lower.endswith(".txt") or file_lower.endswith(".json") or file_lower.endswith(".sqlite") or file_lower.endswith(".log")
    return False

def is_card_path(root_lower: str, file_lower: str) -> bool:
    """Checks if a file is an autofill or card file by directory or filename."""
    keywords = ["card", "credit", "autofill", "cc", "wallet", "payment", "web data", "important", "info"]
    return any(k in root_lower or k in file_lower for k in keywords)

def scan_session_stats(session_path: Path) -> dict:
    """Analyzes unpacked logs to count total files, logs, cookies, passwords, and sessions."""
    stats = {
        "total_files": 0,
        "password_files": 0,
        "cookie_files": 0,
        "card_files": 0,
        "tdata_folders": 0,
        "rdp_files": 0,
        "size_mb": 0.0
    }
    total_bytes = 0

    for root, dirs, files in os.walk(session_path):
        root_l = root.lower()
        for d in dirs:
            if d.lower() == "tdata":
                stats["tdata_folders"] += 1

        for f in files:
            stats["total_files"] += 1
            fl = f.lower()
            fp = Path(root) / f
            try:
                total_bytes += fp.stat().st_size
            except OSError:
                pass

            if fl.endswith(".rdp"):
                stats["rdp_files"] += 1
            if any(p in fl for p in PASSWORD_FILENAMES) or ("password" in root_l and fl.endswith(".txt")):
                stats["password_files"] += 1
            if is_cookie_path(root_l, fl):
                stats["cookie_files"] += 1
            if is_card_path(root_l, fl):
                stats["card_files"] += 1

    stats["size_mb"] = round(total_bytes / (1024 * 1024), 2)
    return stats

def read_file_safe(file_path: Path) -> Optional[str]:
    """Reads file text safely: handles UTF-8, true UTF-16, Latin-1, and extracts printable text from SQLite/binary dumps."""
    try:
        with open(file_path, "rb") as bf:
            raw = bf.read(30 * 1024 * 1024) # Up to 30MB per file

        if not raw:
            return None

        # Check for SQLite files: extract ASCII strings directly
        if raw.startswith(b"SQLite format 3"):
            strings = re.findall(rb"[\x20-\x7E]{4,}", raw)
            return "\n".join(s.decode("latin-1", errors="ignore") for s in strings)

        # Check for true UTF-16 (BOM or regular alternating nulls in text)
        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            try:
                return raw.decode("utf-16", errors="ignore")
            except Exception:
                pass
        elif len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
            try:
                return raw.decode("utf-16-le", errors="ignore")
            except Exception:
                pass

        # Try UTF-8
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass

        # Fallback to Latin-1
        try:
            return raw.decode("latin-1")
        except Exception:
            pass

        # Last resort: extract printable ASCII sequences
        strings = re.findall(rb"[\x20-\x7E]{4,}", raw)
        return "\n".join(s.decode("latin-1", errors="ignore") for s in strings)
    except Exception:
        return None

def search_keywords_in_logs(session_path: Path, keyword: str, max_results: int = 50000) -> Tuple[List[str], int]:
    """
    Intelligent Stealer Log Parser:
    Extracts complete credential blocks (URL, Username, Password) or combo lines
    matching the specified keyword or domain.
    """
    keyword_lower = keyword.strip().lower()
    results = []
    seen = set()
    total_found = 0

    for root, _, files in os.walk(session_path):
        root_l = root.lower()
        for file in files:
            fl = file.lower()
            if fl.endswith(".txt") or any(pf in fl for pf in PASSWORD_FILENAMES) or "password" in root_l:
                file_path = Path(root) / file
                content = read_file_safe(file_path)
                if not content or keyword_lower not in content.lower():
                    continue

                lines = content.splitlines()
                i = 0
                while i < len(lines):
                    line = lines[i]
                    if keyword_lower in line.lower():
                        # Multi-line block format (Redline / Vidar / Lumma)
                        block = []
                        start_idx = max(0, i - 1)
                        end_idx = min(len(lines), i + 6)
                        
                        has_credentials = False
                        for j in range(start_idx, end_idx):
                            l = lines[j].strip()
                            if any(k in l.lower() for k in ["url:", "host:", "soft:", "username:", "user:", "login:", "password:", "pass:"]):
                                has_credentials = True
                                block.append(l)
                            elif block and l.startswith("="):
                                break

                        if has_credentials and len(block) >= 2:
                            entry_text = "\n".join(block)
                            if entry_text not in seen:
                                seen.add(entry_text)
                                total_found += 1
                                if len(results) < max_results:
                                    results.append(entry_text + "\n" + "-" * 40)
                            i = end_idx
                            continue
                        else:
                            # Standard combo line (URL:USER:PASS or USER:PASS)
                            clean_line = line.strip()
                            if clean_line and clean_line not in seen:
                                seen.add(clean_line)
                                total_found += 1
                                if len(results) < max_results:
                                    results.append(clean_line)

                    i += 1

    return results, total_found

def collect_cookies(session_path: Path, output_file: Path) -> Tuple[int, int]:
    """
    Collects all cookie files across the entire session:
    Detects cookies by directory name (Cookies/) as well as filenames.
    Merges all text cookies into output_file.
    Returns (number_of_cookie_files, total_cookie_lines).
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    file_count = 0
    total_lines = 0

    with open(output_file, "w", encoding="utf-8", errors="ignore") as outfile:
        for root, _, files in os.walk(session_path):
            root_l = root.lower()
            for file in files:
                fl = file.lower()
                if is_cookie_path(root_l, fl):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as inf:
                            lines = inf.readlines()
                            if lines:
                                file_count += 1
                                total_lines += len(lines)
                                outfile.write(f"\n# --- Cookie Source: {file_path.name} ({len(lines)} lines) ---\n")
                                outfile.writelines(lines)
                    except Exception:
                        pass

    return file_count, total_lines

def extract_cards_from_sqlite_db(db_path: Path) -> Set[str]:
    """Queries Chromium Web Data SQLite databases directly for credit cards and autofill."""
    found_cards = set()
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        cursor = conn.cursor()
        
        # Check credit_cards table
        try:
            cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
            for row in cursor.fetchall():
                holder = str(row[0] or "").strip()
                mm = str(row[1] or "01").zfill(2)
                yy = str(row[2] or "30")[-2:]
                # Check if card_number is readable in raw text
                card_data = str(row[3] or "")
                num_m = re.search(r"\b(\d{13,19})\b", card_data)
                if num_m:
                    found_cards.add(f"{num_m.group(1)}|{mm}|{yy}||{holder}")
        except Exception:
            pass

        # Check autofill table for card entries
        try:
            cursor.execute("SELECT name, value FROM autofill WHERE name LIKE '%card%' OR name LIKE '%cc%' OR name LIKE '%num%'")
            for row in cursor.fetchall():
                val = str(row[1] or "")
                num_m = re.search(r"\b(\d{13,19})\b", val)
                if num_m:
                    found_cards.add(f"{num_m.group(1)}|01|30||")
        except Exception:
            pass

        conn.close()
    except Exception:
        pass
    return found_cards

def normalize_card_entry(raw_num: str, mm: str, yy: str, cvv: str = "", name: str = "") -> Optional[str]:
    """Sanitizes, validates, and normalizes a card into: NUMBER|MM|YY|CVV|HOLDER."""
    clean_num = re.sub(r"[\s-]", "", raw_num)
    if not (13 <= len(clean_num) <= 19) or not clean_num.isdigit():
        return None

    # Validate month
    clean_mm = mm.strip().lstrip("0")
    if not clean_mm.isdigit():
        return None
    m_int = int(clean_mm)
    if not (1 <= m_int <= 12):
        return None
    month_str = str(m_int).zfill(2)

    # Validate year
    clean_yy = yy.strip()
    if not clean_yy.isdigit():
        return None
    year_str = clean_yy[-2:]

    clean_cvv = cvv.strip()
    clean_name = name.strip()
    return f"{clean_num}|{month_str}|{year_str}|{clean_cvv}|{clean_name}"

def collect_cards(session_path: Path, output_file: Path) -> Tuple[int, int]:
    """
    Maximal Deep Credit Card Harvester:
    Scans every text, autofill, card, sqlite, and log file across the archive.
    Extracts all credit cards across all delimiter styles and multiline formats.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    unique_cards: Set[str] = set()
    files_with_cards = 0

    # Pattern 1: Pure pipe format (NUMBER|MM|YY...)
    re_pipe_line = re.compile(
        r"^\s*([0-9 -]{13,22})\s*\|\s*(\d{1,2})\s*\|\s*(\d{2,4})(?:\s*\|\s*([^|\r\n]*))?(?:\s*\|\s*([^|\r\n]*))?(?:\s*\|\s*([^|\r\n]*))?",
        re.MULTILINE
    )

    # Pattern 2: Delimited formats (NUMBER:MM:YY, NUMBER/MM/YY, NUMBER MM YY)
    re_delimited = re.compile(
        r"(?:\b|\A)([0-9 -]{13,22})\s*[|:;, /]\s*(0?[1-9]|1[0-2])\s*[|:;, /]\s*(\d{2,4})(?:\s*[|:;, /]\s*(\d{3,4}))?(?:\s*[|:;, /]*([^|\r\n\t]*))?",
        re.MULTILINE
    )

    # Pattern 3: Key-Value block patterns
    re_card_num = re.compile(r"(?:card(?:[ _]?number)?|cc(?:[ _]?number)?|number|ccn)\s*[:=]\s*([0-9 -]{13,22})", re.IGNORECASE)
    re_exp_date = re.compile(r"(?:exp(?:iration)?[ _]?(?:date)?|expires)\s*[:=]\s*(0?[1-9]|1[0-2])[ /.-](\d{2,4})", re.IGNORECASE)
    re_exp_m = re.compile(r"(?:exp(?:iration)?[ _]?month|month)\s*[:=]\s*(0?[1-9]|1[0-2])", re.IGNORECASE)
    re_exp_y = re.compile(r"(?:exp(?:iration)?[ _]?year|year)\s*[:=]\s*(\d{2,4})", re.IGNORECASE)
    re_cvv = re.compile(r"(?:cvv2?|cvc2?|security[ _]?code|code)\s*[:=]\s*(\d{3,4})", re.IGNORECASE)
    re_holder = re.compile(r"(?:card[ _]?holder|holder|name[ _]?on[ _]?card|name)\s*[:=]\s*([^\r\n]+)", re.IGNORECASE)

    for root, _, files in os.walk(session_path):
        root_l = root.lower()
        for file in files:
            fl = file.lower()
            ext = Path(fl).suffix

            if ext in NON_CRED_EXTENSIONS:
                continue

            file_path = Path(root) / file
            initial_count = len(unique_cards)

            # SQLite check
            if fl == "web data" or ext in [".sqlite", ".db"]:
                db_cards = extract_cards_from_sqlite_db(file_path)
                unique_cards.update(db_cards)

            content = read_file_safe(file_path)
            if not content:
                if len(unique_cards) > initial_count:
                    files_with_cards += 1
                continue

            # Method 1: Scan pipe lines
            for m in re_pipe_line.finditer(content):
                entry = normalize_card_entry(
                    raw_num=m.group(1),
                    mm=m.group(2),
                    yy=m.group(3),
                    cvv=m.group(4) or "",
                    name=m.group(5) or ""
                )
                if entry:
                    unique_cards.add(entry)

            # Method 2: Scan general delimited lines
            for m in re_delimited.finditer(content):
                entry = normalize_card_entry(
                    raw_num=m.group(1),
                    mm=m.group(2),
                    yy=m.group(3),
                    cvv=m.group(4) or "",
                    name=m.group(5) or ""
                )
                if entry:
                    unique_cards.add(entry)

            # Method 3: Scan multiline blocks
            if any(k in content.lower() for k in ["card", "credit", "cvv", "exp", "autofill"]):
                lines = content.splitlines()
                for idx, line in enumerate(lines):
                    num_m = re_card_num.search(line)
                    if num_m:
                        raw_cnum = num_m.group(1)
                        c_mm, c_yy, c_cvv, c_name = "01", "30", "", ""

                        # Search 8 surrounding lines for attributes
                        window = lines[max(0, idx - 2): min(len(lines), idx + 8)]
                        for w_line in window:
                            if not c_cvv:
                                cv_m = re_cvv.search(w_line)
                                if cv_m:
                                    c_cvv = cv_m.group(1)
                            if not c_name:
                                h_m = re_holder.search(w_line)
                                if h_m and not any(kw in h_m.group(1).lower() for kw in ["card", "number", "exp"]):
                                    c_name = h_m.group(1).strip()
                            exp_m = re_exp_date.search(w_line)
                            if exp_m:
                                c_mm, c_yy = exp_m.group(1), exp_m.group(2)
                            else:
                                em = re_exp_m.search(w_line)
                                if em:
                                    c_mm = em.group(1)
                                ey = re_exp_y.search(w_line)
                                if ey:
                                    c_yy = ey.group(1)

                        entry = normalize_card_entry(raw_cnum, c_mm, c_yy, c_cvv, c_name)
                        if entry:
                            unique_cards.add(entry)

            if len(unique_cards) > initial_count:
                files_with_cards += 1

    # Write all cards to output file
    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.write(f"# Deep Harvested Credit Cards | Total Found: {len(unique_cards)}\n")
        outfile.write("# Format: NUMBER|EXP_MONTH|EXP_YEAR|CVV|HOLDER\n")
        outfile.write("#" + "=" * 60 + "\n\n")
        for card in sorted(unique_cards):
            outfile.write(card + "\n")

    return len(unique_cards), files_with_cards

def collect_all_passwords(session_path: Path, output_file: Path) -> int:
    """Collects all passwords/credentials files into one aggregated file."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(output_file, "w", encoding="utf-8", errors="ignore") as outfile:
        for root, _, files in os.walk(session_path):
            root_l = root.lower()
            for file in files:
                fl = file.lower()
                if any(p in fl for p in PASSWORD_FILENAMES) or ("password" in root_l and fl.endswith(".txt")):
                    count += 1
                    file_path = Path(root) / file
                    outfile.write(f"\n# --- Log File: {file_path.name} ---\n")
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as inf:
                            shutil.copyfileobj(inf, outfile)
                    except Exception:
                        pass
    return count

def package_tdata(session_path: Path, output_zip: Path) -> int:
    """Packages all TData telegram session folders into a single zip archive."""
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    tdata_count = 0
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, _ in os.walk(session_path):
            for d in dirs:
                if d.lower() == "tdata":
                    tdata_count += 1
                    tdata_folder = Path(root) / d
                    for f in tdata_folder.rglob("*"):
                        if f.is_file():
                            arc_path = Path(f"tdata_{tdata_count}") / f.relative_to(tdata_folder)
                            zf.write(f, arcname=str(arc_path))
    return tdata_count

def package_rdp(session_path: Path, output_zip: Path) -> int:
    """Packages all RDP connection files into a zip archive."""
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    rdp_count = 0
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(session_path):
            for file in files:
                if file.lower().endswith(".rdp"):
                    rdp_count += 1
                    fp = Path(root) / file
                    zf.write(fp, arcname=f"rdp_{rdp_count}_{file}")
    return rdp_count
