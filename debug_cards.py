#!/usr/bin/env python3
"""
Debug script — scans session directory and prints what collect_cards finds.
Run: python debug_cards.py <session_folder_path>
Or run without args to scan all active user sessions.
"""
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import USERS_SESSIONS_DIR
from extractor import (
    collect_cards, read_file_safe, luhn_checksum,
    is_card_path, NON_CARD_FILENAMES, NON_CRED_EXTENSIONS,
    parse_cards_from_content
)
import re

def debug_scan(session_path: Path):
    print(f"\n{'='*60}")
    print(f"SESSION: {session_path}")
    print(f"{'='*60}")

    if not session_path.exists():
        print("  [!] Session path does not exist!")
        return

    # List all files
    all_files = []
    for root, _, files in os.walk(session_path):
        for f in files:
            all_files.append(Path(root) / f)

    print(f"\n[+] Total files found: {len(all_files)}")

    # Show dedicated card files
    card_files = []
    skipped_files = []
    for fp in all_files:
        root_l = fp.parent.__str__().lower()
        fl = fp.name.lower()
        ext = fp.suffix.lower()
        if ext in NON_CRED_EXTENSIONS:
            continue
        if fl in NON_CARD_FILENAMES:
            skipped_files.append(fp)
            continue
        if is_card_path(root_l, fl):
            card_files.append(fp)

    print(f"\n[+] Dedicated card/autofill files ({len(card_files)}):")
    for f in card_files[:20]:
        print(f"    {f}")

    print(f"\n[+] Skipped (non-card system files): {len(skipped_files)}")

    # Run Luhn test on any 13-19 digit sequences found in all text files
    print(f"\n[+] Scanning all text files for 13-19 digit sequences (Luhn check)...")
    re_digits = re.compile(r'\b(\d{13,19})\b')
    luhn_hits = []
    luhn_fails = []

    for fp in all_files:
        fl = fp.name.lower()
        if fp.suffix.lower() in NON_CRED_EXTENSIONS:
            continue
        if fl in NON_CARD_FILENAMES:
            continue
        content = read_file_safe(fp)
        if not content:
            continue
        for m in re_digits.finditer(content):
            num = m.group(1)
            if num[0] == '0' or len(set(num)) <= 1:
                continue
            if luhn_checksum(num):
                luhn_hits.append((num, str(fp.relative_to(session_path))))
            else:
                luhn_fails.append((num, str(fp.relative_to(session_path))))

    print(f"\n  LUHN VALID numbers found: {len(luhn_hits)}")
    for num, src in luhn_hits[:30]:
        print(f"    {num}  <- {src}")

    if len(luhn_hits) == 0:
        print(f"\n  LUHN FAILED numbers (first 30 — these are in your logs but NOT Luhn-valid):")
        for num, src in luhn_fails[:30]:
            print(f"    {num}  <- {src}")
        print(f"\n  [!] Total non-Luhn numbers found: {len(luhn_fails)}")
        print(f"  [!] This is why 0 cards are extracted — none pass the Luhn check.")
        print(f"  [!] If these ARE real cards, Luhn validation needs to be disabled.")

    # Run actual collect_cards
    print(f"\n[+] Running full collect_cards...")
    out_file = Path("/tmp/debug_cards_out.txt")
    try:
        total, files_hit = collect_cards(session_path, out_file)
        print(f"  Result: {total} cards from {files_hit} files")
        if total > 0 and out_file.exists():
            print(f"\n  First 20 cards extracted:")
            lines = out_file.read_text(encoding='utf-8', errors='ignore').splitlines()
            for l in lines[:25]:
                print(f"    {l}")
    except Exception as e:
        import traceback
        print(f"  [!] collect_cards CRASHED: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
        debug_scan(target)
    else:
        # Scan all active user sessions
        if not USERS_SESSIONS_DIR.exists():
            print(f"[!] No sessions dir found at {USERS_SESSIONS_DIR}")
            sys.exit(1)
        sessions = list(USERS_SESSIONS_DIR.iterdir())
        if not sessions:
            print("[!] No active sessions found. Upload an archive first then run this.")
            sys.exit(1)
        for s in sessions:
            if s.is_dir():
                debug_scan(s)
