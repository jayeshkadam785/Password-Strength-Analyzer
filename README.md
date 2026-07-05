# 🔐 Password Strength Analyzer

A tool that evaluates password strength in real time, flags common weaknesses,
suggests stronger alternatives, and blocks reuse of a user's old passwords —
built as a cybersecurity fundamentals project.

## Features

- **Length & complexity checks** — flags short passwords and missing character
  classes (uppercase, lowercase, digits, symbols).
- **Pattern detection** — catches sequential runs (`abc`, `123`) and repeated
  characters (`aaa`).
- **Common password detection** — checks against a list of frequently
  breached/weak passwords.
- **Entropy scoring** — estimates strength in bits and maps it to a 0–4 score
  (Very Weak → Very Strong).
- **Strong password generator** — one click to generate a cryptographically
  random 16-character password.
- **Reuse prevention** — stores a **salted PBKDF2-HMAC-SHA256 hash** (never
  plaintext) of each user's last 5 passwords in SQLite, and blocks reuse.
- Available as both a **web UI (Flask)** and a **CLI**.

## Project structure

```
password-strength-analyzer/
├── app.py                 # Flask web app + API routes
├── cli.py                 # Command-line interface
├── analyzer.py             # Core strength/entropy/suggestion logic
├── database.py              # SQLite reuse-prevention (hashed storage)
├── common_passwords.txt      # Small denylist of common weak passwords
├── templates/index.html
├── static/style.css
├── static/script.js
├── requirements.txt
└── .gitignore
```

## Setup

```bash
git clone https://github.com/<your-username>/password-strength-analyzer.git
cd password-strength-analyzer
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web app

```bash
python app.py
```
Open **https://replit.com/@kajaljadhav532/Password-Strength-Analyzer?s=app

### Run the CLI

```bash
python cli.py
```

## How scoring works

1. Character pool size is estimated from which classes are present
   (lowercase, uppercase, digits, symbols).
2. Entropy (bits) ≈ `length × log2(pool size)`.
3. Entropy bands map to a score:

   | Entropy (bits) | Score | Label       |
   |----------------|-------|-------------|
   | < 28            | 0     | Very Weak   |
   | 28–35            | 1     | Weak        |
   | 36–59            | 2     | Moderate    |
   | 60–79            | 3     | Strong      |
   | ≥ 80             | 4     | Very Strong |

4. Using a known common password or personal info (username/email) forces
   the score down regardless of entropy.

## Demo database

This repo ships with a **seeded `passwords.db`** containing sample history for
a `demo_user`, so you can try reuse-detection immediately without setup:

| Username     | Try re-entering (blocked) | Try a new password (allowed) |
|--------------|----------------------------|-------------------------------|
| `demo_user`  | `OldPass123!`, `Summer2024$`, `Tr0ub4dor&Zeb` | anything else |

Only PBKDF2-HMAC-SHA256 salted hashes are stored in this file — never
plaintext. Delete `passwords.db` at any time to start with a clean slate;
`init_db()` will recreate an empty one automatically.

## Security notes (why it's built this way)

- Passwords are **never stored in plaintext**. Only PBKDF2-HMAC-SHA256 hashes
  (260,000 iterations, unique 16-byte salt per entry) are persisted.
- Only the last 5 password hashes per user are kept, matching common
  organizational reuse policies.
- The reuse check happens **before** a password is accepted, not after.

## Learning outcomes

This project is a practical introduction to:
- Password entropy and complexity heuristics
- Salting and key-derivation functions (PBKDF2) vs. plain hashing
- Why storing password history safely (not plaintext) matters
- Building a small full-stack tool (Flask API + vanilla JS frontend)

## License

MIT — free to use and modify for learning purposes.
