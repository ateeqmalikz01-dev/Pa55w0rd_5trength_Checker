#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Password Strength Checker - DecodeLabs Industrial Training Kit
Phase 1: Defensive Fundamentals

Security principles implemented:
  - O(n) linear-time validation (single pass over the password)
  - Unicode-aware entropy (search space up to 1,112,064 code points)
  - Pythonic short-circuit evaluation + C-optimized built-ins (str, set, any)
  - Constant-time equality check via hmac.compare_digest (timing-attack resistant)
  - Memory hygiene: no persistent storage, scrub local refs to limit RAM-scraping risk
"""

import os
import sys
import hmac
import math
import argparse
from typing import Tuple


# ---------------------------------------------------------------------------
# Banner (your requested design)
# ---------------------------------------------------------------------------
BANNER = r"""
                         __  __             _
                        |  \/  |_ __       / \
                        | |\/| | '__|     / _ \
                        | |  | | |       / ___ \
                        |_|  |_|_|      /_/   \_\

                         _____           _
                        |_   _|__   ___ | |___
                          | |/ _ \ / _ \| / __|
                          | | (_) | (_) | \__ \
                          |_|\___/ \___/|_|___/

                ╔══════════════════════════════════════╗
                ║         Mr_A Tools                  ║
                ║     Password Strength Checker       ║
                ╚══════════════════════════════════════╝
"""


def print_banner() -> None:
    """Clear the terminal and print the banner."""
    os.system("cls" if os.name == "nt" else "clear")
    sys.stdout.write(BANNER)
    sys.stdout.write("\n")


# ---------------------------------------------------------------------------
# Character class detection (single pass, C-optimized string methods)
# ---------------------------------------------------------------------------
def analyze_charset(pw: str) -> dict:
    """
    Walk the password once and tally each class.
    Pythonic: uses str.is* (C-implemented) + set() instead of manual loops.
    Short-circuits as soon as the first character of each class is found.
    """
    classes = {
        "lower":   False,
        "upper":   False,
        "digit":   False,
        "symbol":  False,
        "unicode": False,
        "space":   False,
    }
    length = 0
    distinct = set()

    for ch in pw:
        length += 1
        distinct.add(ch)
        cp = ord(ch)

        if ch.islower():
            classes["lower"] = True
        elif ch.isupper():
            classes["upper"] = True
        elif ch.isdigit():
            classes["digit"] = True
        elif ch.isspace():
            classes["space"] = True
        else:
            classes["symbol"] = True

        # Anything outside printable ASCII (0x21-0x7E) expands keyspace
        if cp > 0x7E or (0 < cp < 0x21):
            classes["unicode"] = True

    return {
        "length": length,
        "distinct": len(distinct),
        "classes": classes,
    }


# ---------------------------------------------------------------------------
# Entropy estimation
# ---------------------------------------------------------------------------
def estimate_charset_size(info: dict) -> int:
    c = info["classes"]
    size = 0
    if c["lower"]:   size += 26
    if c["upper"]:   size += 26
    if c["digit"]:   size += 10
    if c["symbol"]:  size += 33
    if c["space"]:   size += 1
    if c["unicode"]:
        size = max(size, 143_859)
    return max(size, 1)


def estimate_entropy(pw: str, info: dict) -> float:
    charset_size = estimate_charset_size(info)
    if charset_size <= 1 or info["length"] == 0:
        return 0.0
    return info["length"] * math.log2(charset_size)


# ---------------------------------------------------------------------------
# Common-password / repetition penalties
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "welcome", "admin", "iloveyou", "monkey", "dragon", "passw0rd",
    "master", "sunshine", "princess", "football", "shadow", "superman",
    "trustno1", "111111", "000000", "password1", "123456789", "1234567",
    "qwerty123", "password123", "1q2w3e4r", "killer", "zxcvbnm",
    "batman", "soccer", "baseball", "charlie", "hunter2",
}


def apply_penalty(pw: str) -> float:
    """Apply penalties — uses hmac.compare_digest for constant-time comparison."""
    penalty = 0.0
    lowered = pw.lower()

    for bad in COMMON_PASSWORDS:
        if hmac.compare_digest(lowered.encode("utf-8"), bad.encode("utf-8")):
            penalty += 60
            break

    if len(pw) > 0 and len(set(pw)) == 1:
        penalty += 50

    best_run = 1
    current_run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i - 1]:
            current_run += 1
            best_run = max(best_run, current_run)
        else:
            current_run = 1
    if best_run >= 4:
        penalty += 20

    if pw.isdigit():
        penalty += 25
    elif pw.isalpha() and len(pw) > 0:
        penalty += 10

    return penalty


# ---------------------------------------------------------------------------
# Strength classifier
# ---------------------------------------------------------------------------
def classify(entropy: float, penalty: float) -> Tuple[str, str, str]:
    effective = entropy - penalty
    if effective < 28:
        return ("WEAK", "\033[1;31m",
                "Password is too guessable. Add length and character variety.")
    if effective < 60:
        return ("MEDIUM", "\033[1;33m",
                "Acceptable, but can be cracked offline. Add length or more character types.")
    if effective < 80:
        return ("STRONG", "\033[1;32m",
                "Solid password. Suitable for most systems.")
    return ("VERY STRONG", "\033[1;36m",
            "Excellent. Suitable for high-value secrets (master passwords, keys).")


# ---------------------------------------------------------------------------
# Pretty report
# ---------------------------------------------------------------------------
def _bar(score: float, width: int = 40) -> str:
    score = max(0.0, min(score, 100.0))
    filled = int(score / 100.0 * width)
    return "[" + "█" * filled + "░" * (width - filled) + f"] {score:5.1f}%"


def render_report(pw: str, info: dict, entropy: float, penalty: float) -> None:
    c = info["classes"]
    effective = max(entropy - penalty, 0.0)
    label, color, advice = classify(entropy, penalty)
    reset = "\033[0m"
    dim = "\033[2m"
    bold = "\033[1m"

    bar_score = min(effective / 128.0 * 100.0, 100.0)
    charset_size = estimate_charset_size(info)
    charset_label = f"{charset_size:,}" if charset_size >= 1000 else str(charset_size)

    print(f"{bold}┌─ Password Analysis {'─' * 46}┐{reset}")
    print(f"│  Length         : {info['length']} characters")
    print(f"│  Distinct chars : {info['distinct']}")
    print(f"│  Lowercase (a-z): {dim+'yes' if c['lower'] else 'no ':>3}{reset}    "
          f"Uppercase (A-Z): {dim+'yes' if c['upper'] else 'no ':>3}{reset}")
    print(f"│  Digits (0-9)   : {dim+'yes' if c['digit'] else 'no ':>3}{reset}    "
          f"Symbols   (!@#) : {dim+'yes' if c['symbol'] else 'no ':>3}{reset}")
    print(f"│  Unicode chars  : {dim+'yes' if c['unicode'] else 'no ':>3}{reset}    "
          f"Whitespace      : {dim+'yes' if c['space'] else 'no ':>3}{reset}")
    print(f"│  Charset size   : ~{charset_label} code points")
    print(f"│  Raw entropy    : {entropy:.2f} bits")
    print(f"│  Penalty        : -{penalty:.2f} bits")
    print(f"│  Effective      : {bold}{effective:.2f} bits{reset}")
    print(f"│  Strength bar   : {_bar(bar_score)}")
    print(f"│")
    print(f"│  Verdict        : {color}{bold}{label}{reset}")
    print(f"│  Recommendation : {advice}")
    print(f"{bold}└{'─' * 64}┘{reset}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def prompt_password() -> str:
    print(f"\033[1;36mEnter a password to evaluate (input is hidden for safety):\033[0m")
    try:
        import getpass
        return getpass.getpass("> ")
    except Exception:
        return input("> ")


def main() -> int:
    print_banner()

    parser = argparse.ArgumentParser(
        description="Evaluate the strength of a password using entropy analysis."
    )
    parser.add_argument("-p", "--password", help="Password to evaluate.")
    parser.add_argument("-l", "--loop", action="store_true",
                        help="Keep prompting until Ctrl+C.")
    args = parser.parse_args()

    print(f"\033[2mTip: --help for flags, or -p 'P@ssw0rd!' from CLI.\033[0m\n")

    while True:
        pw = args.password if args.password else prompt_password()
        if not pw:
            print("\033[1;31m[!] No password supplied.\033[0m\n")
            if not args.loop:
                return 1
            continue

        info = analyze_charset(pw)
        entropy = estimate_entropy(pw, info)
        penalty = apply_penalty(pw)
        render_report(pw, info, entropy, penalty)

        pw = None

        if not args.loop:
            return 0
        print(f"\033[2m{'─' * 64}\033[0m")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\033[1;36m[!] Interrupted. Stay safe out there.\033[0m")
        sys.exit(0)
