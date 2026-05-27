"""
FaceAuthBank — Flask REST API Backend
Bridges the HTML frontend to the SQLite database and face_data directory.
Face auth is simulated in-browser (webcam via face-api.js or simulation),
so this backend handles all data persistence, user management, and transactions.
"""

import sqlite3
import uuid
import random
import json
import logging
import os
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from face_engine import enroll_face, verify_face, has_enrollment, delete_enrollment

# ─── Config ───────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_FILE   = os.path.join(BASE_DIR, "face_auth_bank.db")
FACE_DIR  = os.path.join(BASE_DIR, "face_data")
LOG_FILE  = os.path.join(BASE_DIR, "bank_log.txt")
ADMIN_PW  = "admin123"

os.makedirs(FACE_DIR, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(message)s")

app = Flask(__name__, static_folder=BASE_DIR)

# ─── CORS (manual, no flask-cors needed) ─────────────────
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return resp

@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200

# ─── DB helpers ──────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id     TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            fname       TEXT,
            lname       TEXT,
            email       TEXT UNIQUE,
            phone       TEXT,
            dob         TEXT,
            acct_no     TEXT UNIQUE,
            acct_type   TEXT DEFAULT 'savings',
            balance     REAL DEFAULT 0.0,
            id_type     TEXT,
            id_number   TEXT,
            nominee     TEXT,
            relation    TEXT,
            address     TEXT,
            created_at  TEXT,
            active      INTEGER DEFAULT 1,
            total_credited REAL DEFAULT 0.0,
            total_debited  REAL DEFAULT 0.0
        );
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id         TEXT PRIMARY KEY,
            user_id       TEXT,
            tx_type       TEXT,
            amount        REAL,
            description   TEXT,
            balance_after REAL,
            ref_no        TEXT,
            cls           TEXT,
            icon          TEXT,
            timestamp     TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS auth_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT,
            event_type TEXT,
            message    TEXT,
            timestamp  TEXT
        );
        CREATE TABLE IF NOT EXISTS cards (
            card_id  TEXT PRIMARY KEY,
            user_id  TEXT,
            type     TEXT,
            num      TEXT,
            expiry   TEXT,
            cvv      TEXT,
            virtual  INTEGER DEFAULT 1,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS fixed_deposits (
            fd_id    TEXT PRIMARY KEY,
            user_id  TEXT,
            amount   REAL,
            tenure   INTEGER,
            maturity TEXT,
            ref_no   TEXT,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS loans (
            loan_id  TEXT PRIMARY KEY,
            user_id  TEXT,
            amount   REAL,
            tenure   INTEGER,
            emi      REAL,
            ref_no   TEXT,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
    """)
    conn.commit()
    conn.close()

def gen_acct_no():
    return "520" + str(random.randint(1_000_000_000, 9_999_999_999))

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_auth(conn, user_id, event_type, message):
    conn.execute(
        "INSERT INTO auth_log (user_id, event_type, message, timestamp) VALUES (?,?,?,?)",
        (user_id, event_type, message, now_str())
    )
    conn.commit()
    logging.info(f"[{event_type}] {message}")

def record_tx(conn, user_id, tx_type, amount, description, balance_after, cls, icon):
    ref   = "REF" + uuid.uuid4().hex[:8].upper()
    tx_id = uuid.uuid4().hex
    conn.execute("""
        INSERT INTO transactions
        (tx_id, user_id, tx_type, amount, description, balance_after, ref_no, cls, icon, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (tx_id, user_id, tx_type, amount, description, balance_after, ref, cls, icon, now_str()))
    conn.commit()
    return ref

def row_to_dict(row):
    return dict(row) if row else None

def user_json(row):
    """Convert user row to safe JSON-friendly dict."""
    d = row_to_dict(row)
    if d is None:
        return None
    return d

# ─── Serve frontend ───────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

# ═══════════════════════════════════════════════════════════
# USER ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/users", methods=["GET"])
def list_users():
    """List all active users (for login dropdown)."""
    conn = get_db()
    rows = conn.execute(
        "SELECT user_id, name, fname, lname, acct_no, acct_type, balance, email, phone, active FROM users WHERE active=1"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    """Get full user profile + stats."""
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    u = dict(row)

    # Cards
    cards = conn.execute("SELECT * FROM cards WHERE user_id=?", (user_id,)).fetchall()
    u["cards"] = [dict(c) for c in cards]

    # FDs
    fds = conn.execute("SELECT * FROM fixed_deposits WHERE user_id=?", (user_id,)).fetchall()
    u["fds"] = [dict(f) for f in fds]

    # Loans
    loans = conn.execute("SELECT * FROM loans WHERE user_id=?", (user_id,)).fetchall()
    u["loans"] = [dict(l) for l in loans]

    conn.close()
    return jsonify(u)


@app.route("/api/register", methods=["POST"])
def register():
    """Register a new user. Face auth is simulated on the frontend."""
    data = request.get_json()
    required = ["fname", "lname", "email", "phone", "acct_type"]
    for f in required:
        if not data.get(f):
            return jsonify({"error": f"Missing field: {f}"}), 400

    user_id = "U" + uuid.uuid4().hex[:8].upper()
    acct_no = gen_acct_no()
    name    = data["fname"] + " " + data["lname"]

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO users
            (user_id, name, fname, lname, email, phone, dob, acct_no, acct_type, balance,
             id_type, id_number, nominee, relation, address, created_at, active,
             total_credited, total_debited)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0,0)
        """, (
            user_id, name, data["fname"], data["lname"],
            data["email"], data["phone"], data.get("dob", ""),
            acct_no, data["acct_type"], 0.0,
            data.get("idtype", ""), data.get("idnum", ""),
            data.get("nominee", ""), data.get("relation", ""),
            data.get("addr", ""), now_str()
        ))
        conn.commit()
        log_auth(conn, user_id, "ENROLL", f"Account opened: {name} | {acct_no}")
        logging.info(f"Registered: {name} | {user_id} | {acct_no}")

        conn.close()
        return jsonify({
            "success": True,
            "user_id": user_id,
            "acct_no": acct_no,
            "name": name,
            "acct_type": data["acct_type"]
        })
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"error": str(e)}), 409


@app.route("/api/login", methods=["POST"])
def login():
    """
    Login endpoint.
    face_ok=True means the frontend already called /api/face/verify and got verified=True.
    This endpoint just logs the event and returns user data.
    """
    data    = request.get_json()
    user_id = data.get("user_id")
    face_ok = data.get("face_ok", False)

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    u = dict(row)
    if face_ok:
        log_auth(conn, user_id, "LOGIN_OK", f"Login successful: {u['name']}")
    else:
        log_auth(conn, user_id, "LOGIN_FAIL", f"Login failed (face mismatch): {u['name']}")
        conn.close()
        return jsonify({"error": "Face authentication failed"}), 401

    # Return full user with cards/fds/loans
    cards  = [dict(c) for c in conn.execute("SELECT * FROM cards WHERE user_id=?", (user_id,)).fetchall()]
    fds    = [dict(f) for f in conn.execute("SELECT * FROM fixed_deposits WHERE user_id=?", (user_id,)).fetchall()]
    loans  = [dict(l) for l in conn.execute("SELECT * FROM loans WHERE user_id=?", (user_id,)).fetchall()]
    conn.close()

    u["cards"] = cards
    u["fds"]   = fds
    u["loans"] = loans
    return jsonify({"success": True, "user": u})


# ═══════════════════════════════════════════════════════════
# TRANSACTION ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/transactions/<user_id>", methods=["GET"])
def get_transactions(user_id):
    """Get transaction history for a user."""
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM transactions WHERE user_id=? ORDER BY timestamp DESC LIMIT 50
    """, (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/deposit", methods=["POST"])
def deposit():
    data    = request.get_json()
    user_id = data.get("user_id")
    amount  = float(data.get("amount", 0))
    src     = data.get("source", "Cash Deposit")
    face_ok = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    new_bal = row["balance"] + amount
    conn.execute("UPDATE users SET balance=?, total_credited=total_credited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "CREDIT", amount, f"Cash Deposit — {src}", new_bal, "cr", "💰")
    log_auth(conn, user_id, "DEPOSIT", f"Deposited ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/withdraw", methods=["POST"])
def withdraw():
    data    = request.get_json()
    user_id = data.get("user_id")
    amount  = float(data.get("amount", 0))
    mode    = data.get("mode", "Cash Withdrawal")
    face_ok = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400
    if amount > 50000:
        return jsonify({"error": "Max ₹50,000 per withdrawal"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    if amount > row["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient funds"}), 400

    new_bal = row["balance"] - amount
    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "DEBIT", amount, f"Cash Withdrawal — {mode}", new_bal, "dr", "💸")
    log_auth(conn, user_id, "WITHDRAWAL", f"Withdrew ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/transfer", methods=["POST"])
def transfer():
    data       = request.get_json()
    user_id    = data.get("user_id")
    to_user_id = data.get("to_user_id")
    amount     = float(data.get("amount", 0))
    remark     = data.get("remark", "Fund Transfer")
    face_ok    = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400
    if user_id == to_user_id:
        return jsonify({"error": "Cannot transfer to same account"}), 400

    conn = get_db()
    sender    = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    recipient = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (to_user_id,)).fetchone()

    if not sender or not recipient:
        conn.close()
        return jsonify({"error": "Account not found"}), 404
    if amount > sender["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient funds"}), 400

    new_bal_s = sender["balance"] - amount
    new_bal_r = recipient["balance"] + amount

    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal_s, amount, user_id))
    conn.execute("UPDATE users SET balance=?, total_credited=total_credited+? WHERE user_id=?",
                 (new_bal_r, amount, to_user_id))

    ref = record_tx(conn, user_id, "TRANSFER_OUT", amount,
                    f"Transfer → {recipient['name']} · {remark}", new_bal_s, "tr", "🔄")
    record_tx(conn, to_user_id, "TRANSFER_IN", amount,
              f"Transfer from {sender['name']} · {remark}", new_bal_r, "cr", "🔄")

    log_auth(conn, user_id, "TRANSFER",
             f"Sent ₹{amount} to {recipient['name']} | Ref: {ref}")
    conn.commit()
    conn.close()

    return jsonify({
        "success": True, "new_balance": new_bal_s,
        "ref": ref, "recipient_name": recipient["name"]
    })


@app.route("/api/neft", methods=["POST"])
def neft():
    data    = request.get_json()
    user_id = data.get("user_id")
    amount  = float(data.get("amount", 0))
    name    = data.get("name", "")
    acc     = data.get("acc", "")
    ifsc    = data.get("ifsc", "")
    face_ok = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount <= 0 or not name or not acc or not ifsc:
        return jsonify({"error": "Invalid NEFT details"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    if amount > row["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient funds"}), 400

    new_bal = row["balance"] - amount
    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "NEFT", amount,
                    f"NEFT → {name} ({acc})", new_bal, "tr", "📱")
    log_auth(conn, user_id, "NEFT", f"NEFT ₹{amount} to {name} ({acc}) | Ref: {ref}")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/cheque", methods=["POST"])
def cheque():
    data    = request.get_json()
    user_id = data.get("user_id")
    amount  = float(data.get("amount", 0))
    payee   = data.get("payee", "")
    chq_type = data.get("chq_type", "Bearer Cheque")
    face_ok = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount <= 0 or not payee:
        return jsonify({"error": "Invalid cheque details"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row or amount > row["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient funds or user not found"}), 400

    new_bal = row["balance"] - amount
    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "CHEQUE", amount,
                    f"{chq_type} to {payee}", new_bal, "ch", "📝")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/fd", methods=["POST"])
def create_fd():
    data    = request.get_json()
    user_id = data.get("user_id")
    amount  = float(data.get("amount", 0))
    tenure  = int(data.get("tenure", 12))
    face_ok = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount < 1000:
        return jsonify({"error": "Minimum FD ₹1,000"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row or amount > row["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient balance"}), 400

    from datetime import timedelta
    maturity = (datetime.now() + timedelta(days=tenure * 30)).strftime("%d/%m/%Y")
    ref      = "REF" + uuid.uuid4().hex[:8].upper()
    fd_id    = uuid.uuid4().hex

    new_bal = row["balance"] - amount
    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    conn.execute("""
        INSERT INTO fixed_deposits (fd_id, user_id, amount, tenure, maturity, ref_no, created_at)
        VALUES (?,?,?,?,?,?,?)
    """, (fd_id, user_id, amount, tenure, maturity, ref, now_str()))

    record_tx(conn, user_id, "FD", amount, f"Fixed Deposit — {tenure} months", new_bal, "dr", "🏛️")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "new_balance": new_bal, "ref": ref, "maturity": maturity})


@app.route("/api/loan", methods=["POST"])
def create_loan():
    data    = request.get_json()
    user_id = data.get("user_id")
    amount  = float(data.get("amount", 0))
    tenure  = int(data.get("tenure", 12))
    face_ok = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount <= 0 or amount > 500000:
        return jsonify({"error": "Loan must be ₹1–₹5,00,000"}), 400

    r   = 10.5 / 100 / 12
    emi = (amount * r * (1 + r) ** tenure) / ((1 + r) ** tenure - 1) if r else amount / tenure
    ref = "REF" + uuid.uuid4().hex[:8].upper()

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    new_bal = row["balance"] + amount
    conn.execute("UPDATE users SET balance=?, total_credited=total_credited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    conn.execute("""
        INSERT INTO loans (loan_id, user_id, amount, tenure, emi, ref_no, created_at)
        VALUES (?,?,?,?,?,?,?)
    """, (uuid.uuid4().hex, user_id, amount, tenure, emi, ref, now_str()))

    record_tx(conn, user_id, "LOAN", amount,
              f"Personal Loan Disbursed — {tenure} months @ 10.5% p.a.", new_bal, "cr", "💼")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "new_balance": new_bal, "ref": ref, "emi": round(emi, 2)})


@app.route("/api/rd", methods=["POST"])
def create_rd():
    data    = request.get_json()
    user_id = data.get("user_id")
    amount  = float(data.get("amount", 0))
    tenure  = int(data.get("tenure", 12))
    face_ok = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401
    if amount < 500:
        return jsonify({"error": "Minimum RD ₹500/month"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    ref = record_tx(conn, user_id, "RD", amount,
                    f"Recurring Deposit — ₹{amount}/month × {tenure} months",
                    row["balance"], "dr", "📅")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "ref": ref})


@app.route("/api/card", methods=["POST"])
def issue_card():
    data     = request.get_json()
    user_id  = data.get("user_id")
    card_type = data.get("card_type", "Virtual Debit Card")
    face_ok  = data.get("face_ok", False)

    if not face_ok:
        return jsonify({"error": "Face authentication required"}), 401

    num = "4" + " ".join(
        str(random.randint(1000, 9999)) for _ in range(3)
    )
    mo  = str(random.randint(1, 12)).zfill(2)
    yr  = str((datetime.now().year + 4) % 100).zfill(2)
    exp = f"{mo}/{yr}"
    cvv = str(random.randint(100, 999))
    is_virtual = 1 if "Virtual" in card_type else 0

    conn = get_db()
    card_id = uuid.uuid4().hex
    conn.execute("""
        INSERT INTO cards (card_id, user_id, type, num, expiry, cvv, virtual)
        VALUES (?,?,?,?,?,?,?)
    """, (card_id, user_id, card_type, num, exp, cvv, is_virtual))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "card": {"card_id": card_id, "type": card_type, "num": num,
                 "expiry": exp, "cvv": cvv, "virtual": is_virtual}
    })


@app.route("/api/auth_log/<user_id>", methods=["GET"])
def get_auth_log(user_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM auth_log WHERE user_id=? ORDER BY timestamp DESC LIMIT 30
    """, (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/log_auth", methods=["POST"])
def log_auth_event():
    """Called from frontend to record face auth events (login/tx success/fail)."""
    data    = request.get_json()
    user_id = data.get("user_id", "")
    event   = data.get("event_type", "INFO")
    message = data.get("message", "")
    conn = get_db()
    log_auth(conn, user_id, event, message)
    conn.close()
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════
# ADMIN ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    if data.get("password") != ADMIN_PW:
        return jsonify({"error": "Wrong password"}), 401
    return jsonify({"success": True})


@app.route("/api/admin/summary", methods=["GET"])
def admin_summary():
    pw = request.headers.get("X-Admin-Password", "")
    if pw != ADMIN_PW:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    users       = conn.execute("SELECT COUNT(*) as c FROM users WHERE active=1").fetchone()["c"]
    total_bal   = conn.execute("SELECT SUM(balance) as s FROM users WHERE active=1").fetchone()["s"] or 0
    total_tx    = conn.execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"]
    total_dep   = conn.execute("SELECT SUM(amount) as s FROM transactions WHERE tx_type='CREDIT'").fetchone()["s"] or 0
    total_wd    = conn.execute("SELECT SUM(amount) as s FROM transactions WHERE tx_type='DEBIT'").fetchone()["s"] or 0
    total_tr    = conn.execute("SELECT SUM(amount) as s FROM transactions WHERE tx_type='TRANSFER_OUT'").fetchone()["s"] or 0
    auth_ok     = conn.execute("SELECT COUNT(*) as c FROM auth_log WHERE event_type LIKE '%OK%'").fetchone()["c"]
    auth_fail   = conn.execute("SELECT COUNT(*) as c FROM auth_log WHERE event_type LIKE '%FAIL%'").fetchone()["c"]
    conn.close()

    return jsonify({
        "users": users, "total_balance": total_bal,
        "total_transactions": total_tx, "total_deposits": total_dep,
        "total_withdrawals": total_wd, "total_transfers": total_tr,
        "auth_success": auth_ok, "auth_failures": auth_fail
    })


@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    pw = request.headers.get("X-Admin-Password", "")
    if pw != ADMIN_PW:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    rows = conn.execute("""
        SELECT u.user_id, u.name, u.acct_no, u.acct_type, u.balance,
               u.email, u.phone, u.created_at, u.active,
               COUNT(t.tx_id) as tx_count
        FROM users u
        LEFT JOIN transactions t ON u.user_id = t.user_id
        GROUP BY u.user_id ORDER BY u.created_at DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/transactions", methods=["GET"])
def admin_transactions():
    pw = request.headers.get("X-Admin-Password", "")
    if pw != ADMIN_PW:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    rows = conn.execute("""
        SELECT t.*, u.name FROM transactions t
        JOIN users u ON t.user_id = u.user_id
        ORDER BY t.timestamp DESC LIMIT 100
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/auth_logs", methods=["GET"])
def admin_auth_logs():
    pw = request.headers.get("X-Admin-Password", "")
    if pw != ADMIN_PW:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    rows = conn.execute("""
        SELECT a.*, u.name FROM auth_log a
        LEFT JOIN users u ON a.user_id = u.user_id
        ORDER BY a.timestamp DESC LIMIT 80
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/deactivate", methods=["POST"])
def admin_deactivate():
    pw = request.headers.get("X-Admin-Password", "")
    if pw != ADMIN_PW:
        return jsonify({"error": "Unauthorized"}), 401

    data    = request.get_json()
    user_id = data.get("user_id")
    conn    = get_db()
    conn.execute("UPDATE users SET active=0 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════
# REAL FACE RECOGNITION ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/face/enroll", methods=["POST"])
def face_enroll():
    """
    Enroll a user's face.
    Expects: { user_id, frames: [base64, ...] }  (1-5 frames for better accuracy)
    Trains LBPH model → saves face_data/<user_id>_lbph.yml
    """
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    frames  = data.get("frames", [])

    if not user_id:
        return jsonify({"success": False, "error": "user_id required"}), 400
    if not frames:
        return jsonify({"success": False, "error": "No image frames provided"}), 400

    # Verify user exists in DB
    conn = get_db()
    row  = conn.execute("SELECT name FROM users WHERE user_id=?", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "User not found in database"}), 404

    result = enroll_face(user_id, frames)

    if result["success"]:
        log_auth(conn, user_id, "FACE_ENROLL",
                 f"Face enrolled: {row['name']} ({result['faces_used']} samples)")

    conn.close()
    return jsonify(result)


@app.route("/api/face/verify", methods=["POST"])
def face_verify():
    """
    Verify a face against enrolled model.
    Expects: { user_id, frame: base64_string, threshold?: float }
    Returns: { verified, confidence, match_quality, error? }
    """
    data      = request.get_json()
    user_id   = data.get("user_id", "").strip()
    frame_b64 = data.get("frame", "")
    threshold = float(data.get("threshold", 75.0))

    if not user_id or not frame_b64:
        return jsonify({"verified": False, "error": "user_id and frame required"}), 400

    if not has_enrollment(user_id):
        return jsonify({
            "verified": False,
            "confidence": 999.0,
            "error": "No face enrolled for this user. Please re-register."
        }), 404

    result = verify_face(user_id, frame_b64, threshold=threshold)

    # Log the auth event
    conn = get_db()
    row  = conn.execute("SELECT name FROM users WHERE user_id=?", (user_id,)).fetchone()
    name = row["name"] if row else user_id

    if result["verified"]:
        log_auth(conn, user_id, "FACE_VERIFY_OK",
                 f"Face verified: {name} | confidence={result['confidence']:.1f} | quality={result.get('match_quality','?')}")
    else:
        log_auth(conn, user_id, "FACE_VERIFY_FAIL",
                 f"Face mismatch: {name} | confidence={result['confidence']:.1f} | error={result.get('error','')}")
    conn.close()

    return jsonify(result)


@app.route("/api/face/status/<user_id>", methods=["GET"])
def face_status(user_id):
    """Check if a user has a face enrolled."""
    return jsonify({"enrolled": has_enrollment(user_id), "user_id": user_id})


# ─── Run ─────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n" + "═" * 55)
    print("  🏦  FaceAuthBank API Server")
    print("═" * 55)
    print("  Frontend : http://localhost:5000/")
    print("  API Base : http://localhost:5000/api/")
    print("═" * 55 + "\n")
    app.run(debug=True, port=5000)
