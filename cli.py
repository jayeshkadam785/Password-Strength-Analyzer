"""
cli.py
Command-line interface for the Password Strength Analyzer.

Usage:
    python cli.py
"""

import getpass

from analyzer import analyze_password, suggest_strong_password
from database import init_db, is_password_reused, save_password

BAR = "─" * 44


def print_report(report: dict) -> None:
    print(BAR)
    print(f" Strength : {report['label']}  (score {report['score']}/4)")
    print(f" Entropy  : {report['entropy_bits']} bits")
    print(f" Length   : {report['length']} characters")
    print(BAR)
    print(" Suggestions:")
    for s in report["suggestions"]:
        print(f"   - {s}")
    print(BAR)


def main():
    init_db()
    print("=== Password Strength Analyzer ===")
    username = input("Username (for reuse-check, optional): ").strip()
    password = getpass.getpass("Enter password to evaluate: ")

    report = analyze_password(password, user_inputs=[username])

    if username and is_password_reused(username, password):
        print("\n⚠️  This password matches one you've used before!")
        report["score"] = 0
        report["label"] = "Reused Password"

    print_report(report)

    if report["score"] < 3:
        print(f"\nNeed inspiration? Here's a strong suggestion:\n  {suggest_strong_password()}")

    if username and report["score"] >= 3:
        choice = input("\nSave this password to your history? (y/n): ").strip().lower()
        if choice == "y":
            save_password(username, password)
            print("Saved.")


if __name__ == "__main__":
    main()
