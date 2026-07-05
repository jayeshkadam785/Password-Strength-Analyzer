"""
analyzer.py
Core password strength evaluation logic.

Covers:
- Length check
- Complexity check (uppercase, lowercase, digits, symbols)
- Common/weak password detection
- Basic entropy (bits) calculation -> maps to a 0-4 strength score
- Suggestions to strengthen the password
"""

import math
import re
import os

COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "common_passwords.txt")

STRENGTH_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Moderate",
    3: "Strong",
    4: "Very Strong",
}


def _load_common_passwords():
    try:
        with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = _load_common_passwords()


def _character_pool_size(password: str) -> int:
    """Estimate the size of the character pool used, for entropy calculation."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approx count of common symbols
    return pool or 1


def calculate_entropy(password: str) -> float:
    """Shannon-style entropy estimate in bits: length * log2(pool size)."""
    pool_size = _character_pool_size(password)
    return round(len(password) * math.log2(pool_size), 2)


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Detects simple ascending sequences like 'abc', '123', 'xyz'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        chunk = lowered[i:i + run_length]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


def has_repeated_chars(password: str, repeat_count: int = 3) -> bool:
    """Detects characters repeated back-to-back, e.g. 'aaa', '111'."""
    return bool(re.search(r"(.)\1{" + str(repeat_count - 1) + ",}", password))


def analyze_password(password: str, user_inputs: list[str] | None = None) -> dict:
    """
    Analyze a password and return a report dict:
    {
        score: int (0-4),
        label: str,
        entropy_bits: float,
        checks: {...bool flags...},
        suggestions: [str, ...]
    }
    """
    user_inputs = [u.lower() for u in (user_inputs or []) if u]
    suggestions = []
    checks = {}

    length = len(password)
    checks["length_ok"] = length >= 12
    checks["has_lower"] = bool(re.search(r"[a-z]", password))
    checks["has_upper"] = bool(re.search(r"[A-Z]", password))
    checks["has_digit"] = bool(re.search(r"\d", password))
    checks["has_symbol"] = bool(re.search(r"[^a-zA-Z0-9]", password))
    checks["not_common"] = password.lower() not in COMMON_PASSWORDS
    checks["no_sequential"] = not has_sequential_chars(password)
    checks["no_repeats"] = not has_repeated_chars(password)
    checks["not_personal_info"] = not any(
        u and len(u) >= 3 and u in password.lower() for u in user_inputs
    )

    if length < 8:
        suggestions.append("Use at least 12 characters — longer passwords are much harder to crack.")
    elif length < 12:
        suggestions.append("Consider extending to 12+ characters for stronger protection.")

    if not checks["has_upper"]:
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not checks["has_lower"]:
        suggestions.append("Add at least one lowercase letter (a-z).")
    if not checks["has_digit"]:
        suggestions.append("Add at least one number (0-9).")
    if not checks["has_symbol"]:
        suggestions.append("Add at least one special character (e.g. !@#$%).")
    if not checks["not_common"]:
        suggestions.append("This password is on a list of commonly used/breached passwords — avoid it entirely.")
    if not checks["no_sequential"]:
        suggestions.append("Avoid sequential patterns like 'abc' or '123'.")
    if not checks["no_repeats"]:
        suggestions.append("Avoid repeating the same character multiple times in a row.")
    if not checks["not_personal_info"]:
        suggestions.append("Avoid using your name, username, or email in your password.")

    entropy = calculate_entropy(password)

    # Score 0-4 based on entropy bits, penalized for failed checks.
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4

    critical_fails = sum([
        not checks["not_common"],
        not checks["not_personal_info"],
    ])
    score = max(0, score - critical_fails * 2)

    if not suggestions:
        suggestions.append("Great job! This password meets all recommended criteria.")

    return {
        "score": score,
        "label": STRENGTH_LABELS[score],
        "entropy_bits": entropy,
        "length": length,
        "checks": checks,
        "suggestions": suggestions,
    }


def suggest_strong_password(length: int = 16) -> str:
    """Generate a cryptographically strong random password suggestion."""
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # Ensure it satisfies all complexity rules
        if (re.search(r"[a-z]", pwd) and re.search(r"[A-Z]", pwd)
                and re.search(r"\d", pwd) and re.search(r"[^a-zA-Z0-9]", pwd)):
            return pwd
