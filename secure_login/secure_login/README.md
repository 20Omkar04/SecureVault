# SecureVault — Secure Login Web App

A production-ready Flask authentication system with bcrypt password hashing, CSRF protection, session management, account lockout, and TOTP-based two-factor authentication.

---

## Quick Start

```bash
# 1. Create a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set a secret key (optional — auto-generated on each start if not set)
export SECRET_KEY="your-long-random-secret-here"

# 4. Run
python app.py
```

Open http://localhost:5000 in your browser.

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| Password hashing | **bcrypt** via Flask-Bcrypt (work factor 12) |
| SQL injection protection | **Parameterised queries** throughout — no string formatting |
| Session management | **Flask server-side sessions**, HTTPOnly + SameSite cookies |
| CSRF protection | **Flask-WTF** CSRF tokens on every POST form |
| Input validation | Regex + server-side checks on all user inputs |
| Brute-force protection | Account **lockout after 5 failed logins** (15-min cooldown) |
| Two-factor authentication | **TOTP (RFC 6238)** via pyotp — compatible with Google Authenticator, Authy, 1Password |

---

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Redirects to dashboard or login |
| `/register` | GET, POST | Create a new account |
| `/login` | GET, POST | Sign in |
| `/verify-2fa` | GET, POST | Enter TOTP code (if 2FA enabled) |
| `/dashboard` | GET | Protected dashboard |
| `/setup-2fa` | GET, POST | Enable 2FA — shows QR code |
| `/disable-2fa` | POST | Disable 2FA |
| `/logout` | POST | Clears session |

---

## Password Policy

Passwords must contain at least:
- 8 characters
- One uppercase letter
- One lowercase letter
- One number

The register page includes a live strength meter and rule checklist.

---

## Two-Factor Authentication (TOTP)

1. Go to Dashboard → Security → **Enable 2FA**
2. Scan the QR code with Google Authenticator, Authy, or any TOTP app
3. Enter the 6-digit code to confirm
4. On future logins, you'll be asked for your TOTP code after your password

Codes auto-submit when all 6 digits are entered.

---

## Production Hardening Checklist

- [ ] Set `SESSION_COOKIE_SECURE = True` (requires HTTPS)
- [ ] Use a persistent `SECRET_KEY` from environment variable
- [ ] Use PostgreSQL instead of SQLite (update `get_db()`)
- [ ] Add rate limiting with Flask-Limiter
- [ ] Add email verification on registration
- [ ] Enable HTTPS (Let's Encrypt / nginx)
- [ ] Set `DEBUG = False`

---

## Project Structure

```
secure_login/
├── app.py                  # Flask app, routes, business logic
├── requirements.txt
├── README.md
├── auth.db                 # SQLite database (auto-created)
├── templates/
│   ├── base.html           # Shared layout, flash messages
│   ├── login.html
│   ├── register.html       # With live password strength meter
│   ├── dashboard.html
│   ├── setup_2fa.html      # QR code display
│   └── verify_2fa.html
└── static/
    ├── css/style.css       # Full design system
    └── js/app.js           # UI interactions
```
