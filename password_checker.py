#!/usr/bin/env python3
"""
password_checker.py

Features:
 - Automatic password strength scoring (0–10 scale)
 - Automatic breach (leak) check with HaveIBeenPwned (requires `requests`)
 - Contextual tips & suggestions always shown
 - Developer signature with contact info
"""

from __future__ import annotations
import argparse
import math
import re
import hashlib
import os
import difflib
from typing import Tuple, Dict, List, Optional

# --- small built-in lists ---
BUILTIN_COMMON = {
    "123456", "password", "12345678", "qwerty", "abc123", "monkey", "letmein",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "1234567", "sunshine",
    "princess", "admin", "welcome", "football", "qazwsx", "password1"
}
BUILTIN_DICT = {"password", "admin", "user", "login", "welcome", "love", "secret", "master", "hello", "service", "system", "pass", "qwerty"}

# ✅ fixed length mapping
LEET_MAP = str.maketrans("430157@$!", "aeloistas")

KEYBOARD_PATTERNS = ["qwerty", "asdfgh", "zxcvbn", "1qaz2wsx", "qazwsx", "password"]

# --- utilities ---
def load_common_list(path: str) -> set:
    if not path:
        return BUILTIN_COMMON.copy()
    if not os.path.isfile(path):
        return BUILTIN_COMMON.copy()
    s = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            p = ln.strip()
            if p:
                s.add(p.lower())
    return s

def estimate_charset_size(pw: str) -> int:
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any((not c.isalnum()) for c in pw)
    size = 0
    if has_lower: size += 26
    if has_upper: size += 26
    if has_digit: size += 10
    if has_symbol: size += 32
    if any(ord(c) > 127 for c in pw): size += 500
    return max(size, 1)

def entropy_bits(pw: str) -> float:
    pool = estimate_charset_size(pw)
    return len(pw) * math.log2(pool)

# --- detectors ---
def has_common_password(pw: str, commons:set) -> bool:
    return pw.lower() in commons

def contains_dictionary_word_fuzzy(pw: str, dictionary:set, threshold:float = 0.78) -> Tuple[bool,str,float]:
    low = pw.lower()
    for w in dictionary:
        if w in low:
            return True, w, 1.0
    leet_rev = low.translate(LEET_MAP)
    for w in dictionary:
        if w in leet_rev:
            return True, w, 0.95
    for w in dictionary:
        ratio = difflib.SequenceMatcher(None, low, w).ratio()
        if ratio >= threshold:
            return True, w, ratio
    parts = re.split(r'\W+', low)
    for part in parts:
        if not part: continue
        for w in dictionary:
            ratio = difflib.SequenceMatcher(None, part, w).ratio()
            if ratio >= threshold:
                return True, w, ratio
    return False, "", 0.0

def detect_repeat_patterns(pw: str) -> Tuple[bool,str]:
    # repeated char like 'aaaa'
    if re.search(r'(.)\1{3,}', pw):
        m = re.search(r'(.)\1{3,}', pw)
        return True, f"repeat_char_{m.group(1)}"
    # repeated sequence like 'abcabc'
    for l in range(1, 1 + len(pw)//2):
        if len(pw) % l == 0:
            chunk = pw[:l]
            if chunk * (len(pw)//l) == pw:
                return True, f"repeated_sequence_{chunk}"
    return False, ""

def detect_sequential_chars(pw: str) -> bool:
    # general sequential detection (letters/digits) window size 4
    seq_len_threshold = 4
    s = pw
    for i in range(len(s) - seq_len_threshold + 1):
        window = s[i:i+seq_len_threshold]
        ords = [ord(c) for c in window]
        diffs = [ords[j+1]-ords[j] for j in range(len(ords)-1)]
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return True
    return False

def detect_keyboard_pattern(pw: str) -> bool:
    low = pw.lower()
    for pat in KEYBOARD_PATTERNS:
        if pat in low:
            return True
    return False

def detect_repeated_numbers(pw: str) -> bool:
    # detect 3 or more repeated digits, e.g. 111 or 0000
    return re.search(r'(\d)\1{2,}', pw) is not None

def detect_numeric_sequence(pw: str) -> bool:
    # find contiguous digit runs and check for ascending/descending runs length >=4
    for m in re.finditer(r'\d{3,}', pw):
        run = m.group()
        L_run = len(run)
        # check windows of length 4..L_run
        for L in range(4, L_run+1):
            for start in range(0, L_run - L + 1):
                window = run[start:start+L]
                nums = [int(ch) for ch in window]
                diffs = [nums[j+1]-nums[j] for j in range(len(nums)-1)]
                if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
                    return True
    return False

# --- scoring ---
def score_password_raw(pw: str, commons:set, dictionary:set) -> Tuple[int, List[str], float]:
    reasons: List[str] = []
    if not pw:
        return 0, ["empty password"], 0.0

    ent = entropy_bits(pw)
    reasons.append(f"entropy_bits={ent:.1f}")

    # base from entropy (0..60)
    base_score = min(ent / 4 * 10, 60)

    # category bonus up to 20
    categories = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any((not c.isalnum()) for c in pw)
    ])
    charset_bonus = min(5 + (categories-1)*5, 20)
    reasons.append(f"categories={categories}")

    # length bonus up to ~12
    if len(pw) >= 16:
        length_bonus = 12
    elif len(pw) >= 12:
        length_bonus = 8
    elif len(pw) >= 8:
        length_bonus = 4
    else:
        length_bonus = 0
    reasons.append(f"length={len(pw)}")

    pen = 0
    # Enforce presence of all 4 character types — heavy penalty if missing
    if not any(c.islower() for c in pw):
        pen += 10; reasons.append("missing lowercase")
    if not any(c.isupper() for c in pw):
        pen += 10; reasons.append("missing uppercase")
    if not any(c.isdigit() for c in pw):
        pen += 10; reasons.append("missing digit")
    if not any((not c.isalnum()) for c in pw):
        pen += 10; reasons.append("missing special char")

    # exact common-password match
    if has_common_password(pw, commons):
        pen += 70
        reasons.append("common password (exact match)")

    # dictionary word detection
    dict_found, dict_word, dict_ratio = contains_dictionary_word_fuzzy(pw, dictionary)
    if dict_found:
        pen += 25
        reasons.append(f"dictionary word match: {dict_word}")

    # repeated patterns (chars/sequence)
    rep_found, rep_desc = detect_repeat_patterns(pw)
    if rep_found:
        pen += 20
        reasons.append(f"repetition detected ({rep_desc})")

    # repeated numbers (1111 etc)
    if detect_repeated_numbers(pw):
        pen += 15
        reasons.append("repeated numbers detected")

    # numeric sequences (1234, 9876) are treated specially (avoid double-penalty)
    if detect_numeric_sequence(pw):
        pen += 15
        reasons.append("numeric sequence detected")
    else:
        # general sequential chars (letters or other runs)
        if detect_sequential_chars(pw):
            pen += 15
            reasons.append("sequential characters")

    # keyboard patterns
    if detect_keyboard_pattern(pw):
        pen += 18
        reasons.append("keyboard pattern")

    # too short
    if len(pw) < 6:
        pen += 30
        reasons.append("too short (<6)")

    raw = base_score + charset_bonus + length_bonus - pen
    raw_clamped = max(0, min(100, int(round(raw))))
    return raw_clamped, reasons, ent

def map_to_10_scale(raw_0_100: int) -> Tuple[int, str]:
    val = int(round(raw_0_100 / 10.0))
    val = max(0, min(10, val))
    if val <= 1:
        label = "Very Weak"
    elif val <= 3:
        label = "Weak"
    elif val <= 5:
        label = "Fair"
    elif val <= 7:
        label = "Good"
    elif val <= 9:
        label = "Strong"
    else:
        label = "Excellent"
    return val, label

# --- HIBP breach check ---
def check_pwned(password: str) -> int:
    try:
        import requests
    except ImportError:
        raise RuntimeError("requests required (pip install requests)")
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"HIBP API error: {resp.status_code}")
    for line in resp.text.splitlines():
        h, c = line.split(":")
        if h == suffix:
            return int(c)
    return 0

# --- tips ---
def generate_tips(pw: str, raw_score:int, reasons:List[str], entropy:float, breach_count: Optional[int]) -> List[str]:
    tips: List[str] = []
    if entropy < 40:
        tips.append("Increase length — add words or extra characters (aim for entropy > 60 bits).")
    elif entropy < 60:
        tips.append("Good entropy but you can improve by adding length or mixing character classes.")
    else:
        tips.append("Entropy looks strong — length and charset are good.")

    if "common password (exact match)" in reasons:
        tips.append("Avoid common passwords (e.g., '123456', 'password'). Use a unique passphrase.")
    if any("dictionary word match" in r for r in reasons):
        tips.append("Avoid dictionary words or leet substitutions — use multiple unrelated words.")
    if any("repetition detected" in r for r in reasons):
        tips.append("Don't repeat the same character or sequence — use passphrases.")
    if "numeric sequence detected" in reasons or "sequential characters" in reasons or "keyboard pattern" in reasons:
        tips.append("Avoid sequences like '1234', 'abcd' or keyboard walks like 'qwerty'.")
    if len(pw) < 8:
        tips.append("Use at least 12 characters; 16+ is better for sensitive accounts.")

    categories = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any((not c.isalnum()) for c in pw)
    ])
    if categories < 3 and len(pw) < 12:
        tips.append("Mix uppercase, lowercase, digits, and symbols — or use a long passphrase.")

    if breach_count is not None:
        if breach_count == 0:
            tips.append("No matches in the HIBP breach database (good).")
        else:
            tips.append(f"⚠ This password appears in breaches {breach_count} time(s). Do not use it. Replace immediately.")

    tips.append("Use a password manager to generate/store unique passwords.")
    tips.append("Enable multi-factor authentication (MFA) where available.")
    return tips

# --- signature ---
def pretty_signature(username: str) -> str:
    block = [
        "╔" + "═"*50 + "╗",
        f"║  Password Checker — crafted by {username}".ljust(50) + "  ║",
        "║  Cyber Security Enthusiast".ljust(50) + "  ║",
        "║  Contact: technicalparam@outlook.com".ljust(50) + "  ║",
        "╚" + "═"*50 + "╝"
    ]
    return "\n".join(block)

# --- output ---
def pretty_print_report(report: dict, devname: str="param"):
    print(pretty_signature(devname))
    print(f"Score: {report['score_10']} / 10    Label: {report['label']}")
    print(f"Entropy estimate: {report['entropy']:.1f} bits")
    print("Reasons:")
    for r in report.get("reasons", []):
        print(" -", r)
    if "breach_count" in report:
        bc = report["breach_count"]
        if bc is None:
            print("Leak-check: failed or not performed")
        elif bc == 0:
            print("Leak-check: no matches in HIBP")
        elif bc > 0:
            print(f"Leak-check: found {bc} matches in breach data (unsafe).")
    print("\nSuggestions & Tips:")
    for tip in report.get("tips", [])[:10]:
        print(" •", tip)

# --- CLI main ---
def main():
    parser = argparse.ArgumentParser(description="Password Checker (0-10 scoring) - by param")
    parser.add_argument("password", nargs="?", help="Password to check (omit for interactive)")
    parser.add_argument("--interactive", action="store_true", help="Run interactive prompt")
    parser.add_argument("--common-file", metavar="path", help="Optional path to common-passwords file")
    parser.add_argument("--username", default="param", help="Developer signature name (default: param)")
    args = parser.parse_args()

    commons = load_common_list(args.common_file) if args.common_file else BUILTIN_COMMON.copy()
    dictionary = BUILTIN_DICT.copy()

    def check_and_output(pw: str):
        raw, reasons, ent = score_password_raw(pw, commons, dictionary)

        # automatic leak check (HIBP). If found (>0) we force a fail (raw = 0)
        try:
            breach_count = check_pwned(pw)
        except Exception as e:
            breach_count = None
            reasons.append(f"leak-check failed: {e}")

        if breach_count is not None and breach_count > 0:
            # immediate fail if leaked
            reasons.append(f"found in breach database: {breach_count} matches")
            raw = 0

        score10, label = map_to_10_scale(raw)
        tips = generate_tips(pw, raw, reasons, ent, breach_count)
        report = {
            "score_10": score10,
            "label": label,
            "entropy": ent,
            "reasons": reasons,
            "breach_count": breach_count,
            "tips": tips
        }
        pretty_print_report(report, devname=args.username)

    if args.interactive or not args.password:
        try:
            while True:
                pw = input("Enter password to test (enter to quit): ").strip()
                if pw == "":
                    break
                check_and_output(pw)
                print("\n" + "-"*60 + "\n")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting interactive mode.")
    else:
        check_and_output(args.password)

if __name__ == "__main__":
    main()
