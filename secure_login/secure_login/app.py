import os
import re
import io
import base64
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import pyotp
import qrcode
from flask import (Flask, flash, redirect, render_template,
                   request, session, url_for)
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

# ─── App configuration ──────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # set True with HTTPS in production
    WTF_CSRF_TIME_LIMIT=3600,
)

bcrypt = Bcrypt(app)
csrf   = CSRFProtect(app)

DB_PATH       = "auth.db"
MAX_ATTEMPTS  = 5
LOCKOUT_MINS  = 15

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id             INTEGER  PRIMARY KEY AUTOINCREMENT,
                username       TEXT     UNIQUE NOT NULL,
                email          TEXT     UNIQUE NOT NULL,
                password_hash  TEXT     NOT NULL,
                totp_secret    TEXT,
                two_fa_enabled INTEGER  DEFAULT 0,
                login_attempts INTEGER  DEFAULT 0,
                locked_until   TEXT,
                created_at     TEXT     DEFAULT (datetime('now'))
            )
        """)
        conn.commit()

with app.app_context():
    init_db()

# ─── Validators ─────────────────────────────────────────────────────────────

RE_USERNAME = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
RE_EMAIL    = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

def validate_password(pw: str):
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", pw):
        return "Password needs at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return "Password needs at least one lowercase letter."
    if not re.search(r"\d", pw):
        return "Password needs at least one number."
    return None

# ─── Auth decorator ──────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

# ─── QR helper ───────────────────────────────────────────────────────────────

def make_qr_b64(uri: str) -> str:
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#E4EAF5", back_color="#0A1020")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))

# ── Register ─────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method != "POST":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email    = request.form.get("email",    "").strip().lower()
    pw       = request.form.get("password", "")
    pw2      = request.form.get("confirm_password", "")

    errors = []
    if not RE_USERNAME.match(username):
        errors.append("Username: 3–32 chars, letters / numbers / underscore only.")
    if not RE_EMAIL.match(email):
        errors.append("Please enter a valid email address.")
    pw_err = validate_password(pw)
    if pw_err:
        errors.append(pw_err)
    if pw != pw2:
        errors.append("Passwords do not match.")

    if errors:
        for e in errors:
            flash(e, "error")
        return render_template("register.html", username=username, email=email)

    db = get_db()
    try:
        # Parameterised query — no SQL injection possible
        collision = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()
        if collision:
            flash("Username or email already in use.", "error")
            return render_template("register.html", username=username, email=email)

        pw_hash = bcrypt.generate_password_hash(pw).decode()
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, pw_hash)
        )
        db.commit()
    finally:
        db.close()

    flash("Account created — please sign in.", "success")
    return redirect(url_for("login"))

# ── Login ─────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method != "POST":
        return render_template("login.html")

    identifier = request.form.get("username", "").strip()
    pw         = request.form.get("password", "")

    if not identifier or not pw:
        flash("Please fill in all fields.", "error")
        return render_template("login.html", username=identifier)

    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (identifier, identifier.lower())
    ).fetchone()

    # Lockout check
    if user and user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.utcnow() < locked_until:
            mins = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
            flash(f"Account locked. Try again in {mins} minute(s).", "error")
            db.close()
            return render_template("login.html", username=identifier)
        # Lockout expired — reset
        db.execute(
            "UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],)
        )
        db.commit()

    # Constant-time credential check (bcrypt handles timing safety)
    if not user or not bcrypt.check_password_hash(user["password_hash"], pw):
        if user:
            attempts = (user["login_attempts"] or 0) + 1
            if attempts >= MAX_ATTEMPTS:
                lock_ts = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINS)).isoformat()
                db.execute(
                    "UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?",
                    (attempts, lock_ts, user["id"])
                )
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_MINS} min.", "error")
            else:
                db.execute(
                    "UPDATE users SET login_attempts = ? WHERE id = ?",
                    (attempts, user["id"])
                )
                left = MAX_ATTEMPTS - attempts
                flash(f"Invalid credentials. {left} attempt(s) remaining.", "error")
            db.commit()
        else:
            flash("Invalid credentials.", "error")
        db.close()
        return render_template("login.html", username=identifier)

    # Reset attempts on success
    db.execute(
        "UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?",
        (user["id"],)
    )
    db.commit()
    db.close()

    if user["two_fa_enabled"]:
        session["2fa_pending"] = user["id"]
        return redirect(url_for("verify_2fa"))

    session.permanent    = True
    session["user_id"]   = user["id"]
    session["username"]  = user["username"]
    flash(f"Welcome back, {user['username']}!", "success")
    return redirect(url_for("dashboard"))

# ── 2FA Verify ───────────────────────────────────────────────────────────────

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    uid = session.get("2fa_pending")
    if not uid:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").replace(" ", "")
        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        db.close()

        if not user:
            session.pop("2fa_pending", None)
            return redirect(url_for("login"))

        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code, valid_window=1):
            session.pop("2fa_pending", None)
            session.permanent   = True
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid or expired code. Please try again.", "error")

    return render_template("verify_2fa.html")

# ── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()
    return render_template("dashboard.html", user=user)

# ── 2FA Setup ────────────────────────────────────────────────────────────────

@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        code   = request.form.get("code", "").replace(" ", "")
        secret = session.get("totp_setup_secret")

        if not secret:
            flash("Setup session expired — please try again.", "error")
            db.close()
            return redirect(url_for("setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            db.execute(
                "UPDATE users SET totp_secret = ?, two_fa_enabled = 1 WHERE id = ?",
                (secret, session["user_id"])
            )
            db.commit()
            db.close()
            session.pop("totp_setup_secret", None)
            flash("Two-factor authentication is now active.", "success")
            return redirect(url_for("dashboard"))

        flash("Code incorrect — scan the QR code again and try.", "error")
        db.close()
        return redirect(url_for("setup_2fa"))

    # Generate fresh TOTP secret + QR code
    secret  = pyotp.random_base32()
    session["totp_setup_secret"] = secret
    uri     = pyotp.TOTP(secret).provisioning_uri(user["email"], issuer_name="SecureVault")
    qr_b64  = make_qr_b64(uri)
    db.close()
    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret)

# ── Disable 2FA ──────────────────────────────────────────────────────────────

@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = NULL, two_fa_enabled = 0 WHERE id = ?",
        (session["user_id"],)
    )
    db.commit()
    db.close()
    flash("Two-factor authentication disabled.", "info")
    return redirect(url_for("dashboard"))

# ── Logout ───────────────────────────────────────────────────────────────────

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You've been signed out.", "info")
    return redirect(url_for("login"))

# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5000)
