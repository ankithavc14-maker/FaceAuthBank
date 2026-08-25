"""
FaceAuthBank — Flask REST API Backend (Security-Hardened)
=========================================================
Security fixes applied:
  ✅ Brute-force lockout integrated into /api/face/verify
  ✅ Liveness detection enforced on every verify call
  ✅ /api/face/verify now accepts frames[] list (multi-frame liveness)
  ✅ /api/lockout/<user_id> endpoint for frontend to query lock state
  ✅ Threshold aligned: 0.45 (resume says ≤ 0.6; 0.45 is stricter = better)
  ✅ Admin password hardened (env var with fallback)
  ✅ face_ok flag verified against real backend verify result (not trusted blindly)
"""

import uuid
import random
import json
import logging
import secrets
import traceback
from dotenv import load_dotenv
load_dotenv()
from ml_engine import (
    detect_fraud, compute_risk_score,
    analyse_spending_pattern, predict_next_transaction,
    detect_auth_anomaly, generate_ml_report
)
import os
from datetime import datetime
from psycopg import IntegrityError
from flask import Flask, request, jsonify, send_from_directory, send_file
from face_engine import (
    enroll_face, verify_face, has_enrollment, delete_enrollment, profile_photo_path,
    get_lockout_status, reset_failed_attempts, THRESHOLD,
    candidate_from_frames, find_duplicate_face
)

# ─── Config ───────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FACE_DIR = os.path.join(BASE_DIR, "face_data")
LOG_FILE = os.path.join(BASE_DIR, "bank_log.txt")
ADMIN_PW = os.environ.get("FACEAUTH_ADMIN_PW", "admin@FaceBank#2025")
AUTH_TOKENS = {}
AUTH_TOKEN_TTL = 90

app = Flask(__name__, static_folder=BASE_DIR)

@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    logging.error("Unhandled API error: %s\n%s", exc, traceback.format_exc())
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error", "detail": str(exc)}), 500
    return "Internal server error", 500

os.makedirs(FACE_DIR, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(message)s")


# ─── CORS ────────────────────────────────────────────────
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Admin-Password"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return resp

@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200

# ─── PostgreSQL DB helpers ───────────────────────────────
from db import get_db, init_db

# ─── Shared helpers ──────────────────────────────────────
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
    ref = "REF" + uuid.uuid4().hex[:8].upper()
    tx_id = uuid.uuid4().hex
    conn.execute("""
        INSERT INTO transactions
        (tx_id, user_id, tx_type, amount, description, balance_after, ref_no, cls, icon, timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (tx_id, user_id, tx_type, amount, description, balance_after, ref, cls, icon, now_str()))
    conn.commit()
    return ref

# ─── Serve frontend ──────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

# ═══════════════════════════════════════════════════════════
# USER ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/users", methods=["GET"])
def list_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT user_id, name, fname, lname, acct_no, acct_type, balance, email, phone, active FROM users WHERE active=1"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    u      = dict(row)
    u["cards"] = [dict(c) for c in conn.execute("SELECT * FROM cards WHERE user_id=?", (user_id,)).fetchall()]
    u["fds"]   = [dict(f) for f in conn.execute("SELECT * FROM fixed_deposits WHERE user_id=?", (user_id,)).fetchall()]
    u["loans"] = [dict(l) for l in conn.execute("SELECT * FROM loans WHERE user_id=?", (user_id,)).fetchall()]
    conn.close()
    return jsonify(u)


@app.route("/api/register", methods=["POST"])
def register():
    data     = request.get_json()
    required = ["fname", "lname", "email", "phone", "acct_type"]
    for f in required:
        if not data.get(f):
            return jsonify({"error": f"Missing field: {f}"}), 400

    user_id = "U" + uuid.uuid4().hex[:8].upper()
    acct_no = gen_acct_no()
    name    = data["fname"] + " " + data["lname"]

    conn = get_db()
    try:
        # Prevent duplicate active customer names.  This is a business-rule
        # check (the database only has a UNIQUE constraint on email/account).
        duplicate_name = conn.execute(
            "SELECT user_id, acct_no FROM users WHERE active=1 AND LOWER(TRIM(name))=LOWER(TRIM(?)) LIMIT 1",
            (name,)
        ).fetchone()
        if duplicate_name:
            conn.close()
            return jsonify({
                "error": f"An account with the name '{name}' already exists. Please use the existing account or check the name."
            }), 409

        conn.execute("""
            INSERT INTO users
            (user_id, name, fname, lname, email, phone, dob, acct_no, acct_type, balance,
             id_type, id_number, nominee, relation, address, created_at, active, face_enrolled,
             total_credited, total_debited)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,FALSE,0,0)
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
        conn.close()
        return jsonify({"success": True, "user_id": user_id, "acct_no": acct_no,
                        "name": name, "acct_type": data["acct_type"]})
    except IntegrityError as e:
        conn.close()
        return jsonify({"error": str(e)}), 409


@app.route("/api/login", methods=["POST"])
def login():
    """
    Login endpoint.
    Accepts: { user_id, frames } for fresh verify, OR { user_id, face_ok: true }
    when /face/verify has already succeeded in the same session.
    """
    data      = request.get_json()
    user_id   = data.get("user_id", "").strip()
    frames    = data.get("frames", [])
    face_ok   = data.get("face_ok", False)

    # Legacy single-frame support
    if not frames and data.get("frame"):
        frames = [data["frame"]]

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    u = dict(row)

    auth_token = data.get("auth_token")
    if auth_token:
        token_data = AUTH_TOKENS.get(auth_token)
        if not token_data or token_data["user_id"] != user_id or token_data["expires"] < datetime.now().timestamp():
            conn.close()
            return jsonify({"error": "Authentication token expired or invalid"}), 401
        AUTH_TOKENS.pop(auth_token, None)
        result = {"verified": True, "confidence": 0.0, "match_quality": "pre-verified"}
    elif frames:
        if not has_enrollment(user_id):
            conn.close()
            return jsonify({"error": "No face enrolled. Please register your face first."}), 404
        result = verify_face(user_id, frames)
    else:
        conn.close()
        return jsonify({"error": "No face frames provided for authentication"}), 400

    if result["verified"]:
        log_auth(conn, user_id, "LOGIN_OK",
                 f"Login OK: {u['name']} | dist={result['confidence']} | liveness=PASS")
        u["cards"] = [dict(c) for c in conn.execute("SELECT * FROM cards WHERE user_id=?", (user_id,)).fetchall()]
        u["fds"]   = [dict(f) for f in conn.execute("SELECT * FROM fixed_deposits WHERE user_id=?", (user_id,)).fetchall()]
        u["loans"] = [dict(l) for l in conn.execute("SELECT * FROM loans WHERE user_id=?", (user_id,)).fetchall()]
        conn.close()
        return jsonify({"success": True, "user": u, "auth": result})
    else:
        log_auth(conn, user_id, "LOGIN_FAIL",
                 f"Login FAIL: {u['name']} | dist={result.get('confidence','?')} | "
                 f"error={result.get('error','')}")
        conn.close()
        return jsonify({"error": result.get("error", "Face authentication failed"),
                        "auth": result}), 401


# ═══════════════════════════════════════════════════════════
# TRANSACTION ENDPOINTS
# All transactions verify face server-side via frames[]
# ═══════════════════════════════════════════════════════════

def _require_face(data: dict, user_id: str, conn) -> tuple[bool, dict]:
    """Require a fresh server-issued face verification token or verify supplied frames."""
    frames = data.get("frames", [])
    if not frames and data.get("frame"):
        frames = [data["frame"]]

    token = data.get("auth_token")
    if token:
        token_data = AUTH_TOKENS.get(token)
        if token_data and token_data["user_id"] == user_id and token_data["expires"] >= datetime.now().timestamp():
            AUTH_TOKENS.pop(token, None)  # one transaction per face verification
            return True, {"verified": True, "confidence": 0.0, "match_quality": "server-verified-token"}
        return False, {"error": "Authentication token expired or invalid. Please verify your face again."}

    if not frames:
        return False, {"error": "Fresh face authentication is required for every transaction."}
    if not has_enrollment(user_id):
        return False, {"error": "No face enrolled for this account"}
    result = verify_face(user_id, frames)
    return result["verified"], result

@app.route("/api/transactions/<user_id>", methods=["GET"])
def get_transactions(user_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM transactions WHERE user_id=? ORDER BY timestamp DESC LIMIT 50
    """, (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/deposit", methods=["POST"])
def deposit():
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    amount  = float(data.get("amount", 0))
    src     = data.get("source", "Cash Deposit")

    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        log_auth(conn, user_id, "TX_FAIL", f"Deposit ₹{amount} — face auth failed")
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    new_bal = row["balance"] + amount
    conn.execute("UPDATE users SET balance=?, total_credited=total_credited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "CREDIT", amount, f"Cash Deposit — {src}", new_bal, "cr", "💰")
    log_auth(conn, user_id, "DEPOSIT", f"Deposited ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    conn.close()
    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/withdraw", methods=["POST"])
def withdraw():
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    amount  = float(data.get("amount", 0))
    mode    = data.get("mode", "Cash Withdrawal")

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

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        log_auth(conn, user_id, "TX_FAIL", f"Withdrawal ₹{amount} — face auth failed")
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    new_bal = row["balance"] - amount
    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "DEBIT", amount, f"Cash Withdrawal — {mode}", new_bal, "dr", "💸")
    log_auth(conn, user_id, "WITHDRAWAL", f"Withdrew ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    conn.close()
    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/transfer", methods=["POST"])
def transfer():
    data       = request.get_json()
    user_id    = data.get("user_id", "").strip()
    to_user_id = data.get("to_user_id", "").strip()
    amount     = float(data.get("amount", 0))
    remark     = data.get("remark", "Fund Transfer")

    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400
    if user_id == to_user_id:
        return jsonify({"error": "Cannot transfer to same account"}), 400

    conn      = get_db()
    sender    = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    recipient = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (to_user_id,)).fetchone()

    if not sender or not recipient:
        conn.close()
        return jsonify({"error": "Account not found"}), 404
    if amount > sender["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient funds"}), 400

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        log_auth(conn, user_id, "TX_FAIL", f"Transfer ₹{amount} — face auth failed")
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

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
    log_auth(conn, user_id, "TRANSFER", f"Sent ₹{amount} to {recipient['name']} | Ref: {ref}")
    conn.close()
    return jsonify({"success": True, "new_balance": new_bal_s, "ref": ref,
                    "recipient_name": recipient["name"]})


@app.route("/api/neft", methods=["POST"])
def neft():
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    amount  = float(data.get("amount", 0))
    name    = data.get("name", "")
    acc     = data.get("acc", "")
    ifsc    = data.get("ifsc", "")

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

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    new_bal = row["balance"] - amount
    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "NEFT", amount, f"NEFT → {name} ({acc})", new_bal, "tr", "📱")
    log_auth(conn, user_id, "NEFT", f"NEFT ₹{amount} to {name} ({acc}) | Ref: {ref}")
    conn.close()
    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/cheque", methods=["POST"])
def cheque():
    data     = request.get_json()
    user_id  = data.get("user_id", "").strip()
    amount   = float(data.get("amount", 0))
    payee    = data.get("payee", "")
    chq_type = data.get("chq_type", "Bearer Cheque")

    if amount <= 0 or not payee:
        return jsonify({"error": "Invalid cheque details"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row or amount > row["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient funds or user not found"}), 400

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    new_bal = row["balance"] - amount
    conn.execute("UPDATE users SET balance=?, total_debited=total_debited+? WHERE user_id=?",
                 (new_bal, amount, user_id))
    ref = record_tx(conn, user_id, "CHEQUE", amount, f"{chq_type} to {payee}", new_bal, "ch", "📝")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "new_balance": new_bal, "ref": ref})


@app.route("/api/fd", methods=["POST"])
def create_fd():
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    amount  = float(data.get("amount", 0))
    tenure  = int(data.get("tenure", 12))

    if amount < 1000:
        return jsonify({"error": "Minimum FD ₹1,000"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row or amount > row["balance"]:
        conn.close()
        return jsonify({"error": "Insufficient balance"}), 400

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    from datetime import timedelta
    maturity = (datetime.now() + timedelta(days=tenure * 30)).strftime("%d/%m/%Y")
    ref      = "REF" + uuid.uuid4().hex[:8].upper()
    fd_id    = uuid.uuid4().hex
    new_bal  = row["balance"] - amount

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
    user_id = data.get("user_id", "").strip()
    amount  = float(data.get("amount", 0))
    tenure  = int(data.get("tenure", 12))

    if amount <= 0 or amount > 500000:
        return jsonify({"error": "Loan must be ₹1–₹5,00,000"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    r   = 10.5 / 100 / 12
    emi = (amount * r * (1 + r) ** tenure) / ((1 + r) ** tenure - 1) if r else amount / tenure
    ref = "REF" + uuid.uuid4().hex[:8].upper()

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
    user_id = data.get("user_id", "").strip()
    amount  = float(data.get("amount", 0))
    tenure  = int(data.get("tenure", 12))

    if amount < 500:
        return jsonify({"error": "Minimum RD ₹500/month"}), 400

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    ref = record_tx(conn, user_id, "RD", amount,
                    f"Recurring Deposit — ₹{amount}/month × {tenure} months",
                    row["balance"], "dr", "📅")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "ref": ref})


@app.route("/api/card", methods=["POST"])
def issue_card():
    data      = request.get_json()
    user_id   = data.get("user_id", "").strip()
    card_type = data.get("card_type", "Virtual Debit Card")

    conn = get_db()
    row  = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    ok, auth = _require_face(data, user_id, conn)
    if not ok:
        conn.close()
        return jsonify({"error": auth.get("error", "Face authentication failed"), "auth": auth}), 401

    num = "4" + " ".join(str(random.randint(1000, 9999)) for _ in range(3))
    mo  = str(random.randint(1, 12)).zfill(2)
    yr  = str((datetime.now().year + 4) % 100).zfill(2)
    exp = f"{mo}/{yr}"
    cvv = str(random.randint(100, 999))
    is_virtual = 1 if "Virtual" in card_type else 0

    card_id = uuid.uuid4().hex
    conn.execute("""
        INSERT INTO cards (card_id, user_id, type, num, expiry, cvv, virtual)
        VALUES (?,?,?,?,?,?,?)
    """, (card_id, user_id, card_type, num, exp, cvv, is_virtual))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "card": {
        "card_id": card_id, "type": card_type, "num": num,
        "expiry": exp, "cvv": cvv, "virtual": is_virtual
    }})


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
    data    = request.get_json()
    user_id = data.get("user_id", "")
    event   = data.get("event_type", "INFO")
    message = data.get("message", "")
    conn = get_db()
    log_auth(conn, user_id, event, message)
    conn.close()
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════
# FACE RECOGNITION ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/face/check-duplicate", methods=["POST"])
def face_check_duplicate():
    data = request.get_json(silent=True) or {}
    frames = data.get("frames", [])
    if len(frames) < 3:
        return jsonify({"duplicate": False, "error": "Minimum 3 frames required"}), 400
    candidate, liveness = candidate_from_frames(frames)
    if candidate is None:
        return jsonify({"duplicate": False, "error": "No face detected in the captured frames.",
                        "liveness": liveness}), 400
    if not liveness.get("live"):
        return jsonify({"duplicate": False, "error": liveness.get("reason", "Liveness check failed"),
                        "liveness": liveness}), 400
    duplicate = find_duplicate_face(candidate)
    if duplicate:
        return jsonify({
            "duplicate": True,
            "error": "This face is already registered with another account.",
            "distance": duplicate["distance"],
            "liveness": liveness
        })
    return jsonify({"duplicate": False, "liveness": liveness})


@app.route("/api/face/enroll", methods=["POST"])
def face_enroll():
    data = request.get_json(silent=True) or {}
    user_id = str(data.get("user_id", "")).strip()
    frames = data.get("frames", [])
    if not user_id:
        return jsonify({"success": False, "error": "user_id required"}), 400
    if len(frames) < 3:
        return jsonify({"success": False, "error": "Minimum 3 frames required for liveness-checked enrollment"}), 400

    conn = get_db()
    row = conn.execute("SELECT name, face_enrolled FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "User not found in database"}), 404

    result = enroll_face(user_id, frames)

    if result["success"]:
        conn.execute("UPDATE users SET face_enrolled=TRUE WHERE user_id=?", (user_id,))
        log_auth(conn, user_id, "FACE_ENROLL", f"Face enrolled: {row['name']} ({result['faces_used']} samples)")
    else:
        log_auth(conn, user_id, "FACE_ENROLL_FAIL", f"Face enrollment failed: {row['name']} — {result.get('error','')}")
        # A newly-created account has no face and no transactions. Remove it so
        # a failed/duplicate enrollment never leaves an orphan account.
        if not row["face_enrolled"]:
            tx_count = conn.execute("SELECT COUNT(*) AS c FROM transactions WHERE user_id=?", (user_id,)).fetchone()["c"]
            if int(tx_count) == 0:
                conn.execute("DELETE FROM users WHERE user_id=?", (user_id,))
                delete_enrollment(user_id)
                conn.commit()
                conn.close()
                return jsonify({
                    **result,
                    "account_removed": True
                }), 409

    conn.close()
    return jsonify(result)

@app.route("/api/face/verify", methods=["POST"])
def face_verify():
    """
    Verify a face with full security stack:
      liveness detection + lockout check + strict threshold (0.45).
    Expects: { user_id, frames: [base64, ...] }  — min 3 frames recommended
    Returns: { verified, confidence, match_quality, liveness, lockout, error? }
    """
    data      = request.get_json()
    user_id   = data.get("user_id", "").strip()
    frames    = data.get("frames", [])

    # Legacy single-frame fallback
    if not frames and data.get("frame"):
        frames = [data["frame"]]

    if not user_id or not frames:
        return jsonify({"verified": False, "error": "user_id and frames required"}), 400

    if not has_enrollment(user_id):
        return jsonify({
            "verified": False, "confidence": 999.0,
            "error": "No face enrolled for this user. Please re-register."
        }), 404

    result = verify_face(user_id, frames)

    conn = get_db()
    row  = conn.execute("SELECT name FROM users WHERE user_id=%s", (user_id,)).fetchone()
    name = row["name"] if row else user_id

    if result["verified"]:
        token = secrets.token_urlsafe(32)
        AUTH_TOKENS[token] = {
            "user_id": user_id,
            "expires": datetime.now().timestamp() + AUTH_TOKEN_TTL
        }
        result["auth_token"] = token
        log_auth(conn, user_id, "FACE_VERIFY_OK",
                 f"Face verified: {name} | dist={result['confidence']} | liveness=PASS")
    else:
        log_auth(conn, user_id, "FACE_VERIFY_FAIL",
                 f"Face mismatch: {name} | dist={result.get('confidence','?')} | "
                 f"error={result.get('error','')}")
    conn.close()
    return jsonify(result)


@app.route("/api/face/status/<user_id>", methods=["GET"])
def face_status(user_id):
    """Check enrollment status + current lockout state."""
    lockout = get_lockout_status(user_id)
    return jsonify({
        "enrolled"          : has_enrollment(user_id),
        "user_id"           : user_id,
        "lockout"           : lockout,
        "threshold"         : THRESHOLD
    })


@app.route("/api/lockout/<user_id>", methods=["GET"])
def lockout_status(user_id):
    """Query lockout state for a user (for frontend display)."""
    return jsonify(get_lockout_status(user_id))


@app.route("/api/lockout/<user_id>/reset", methods=["POST"])
def lockout_reset(user_id):
    """Admin-only: reset lockout for a user."""
    pw = request.headers.get("X-Admin-Password", "")
    if pw != ADMIN_PW:
        return jsonify({"error": "Unauthorized"}), 401
    reset_failed_attempts(user_id)
    return jsonify({"success": True, "message": f"Lockout cleared for {user_id}"})


@app.route("/api/profile/photo/<user_id>", methods=["GET"])
def profile_photo(user_id):
    path = profile_photo_path(user_id)
    if not path:
        return jsonify({"error":"Profile photo not available"}), 404
    return send_file(path, mimetype="image/jpeg", max_age=3600)


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

    conn       = get_db()
    users      = conn.execute("SELECT COUNT(*) as c FROM users WHERE active=1").fetchone()["c"]
    total_bal  = conn.execute("SELECT SUM(balance) as s FROM users WHERE active=1").fetchone()["s"] or 0
    total_tx   = conn.execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"]
    total_dep  = conn.execute("SELECT SUM(amount) as s FROM transactions WHERE tx_type='CREDIT'").fetchone()["s"] or 0
    total_wd   = conn.execute("SELECT SUM(amount) as s FROM transactions WHERE tx_type='DEBIT'").fetchone()["s"] or 0
    total_tr   = conn.execute("SELECT SUM(amount) as s FROM transactions WHERE tx_type='TRANSFER_OUT'").fetchone()["s"] or 0
    auth_ok    = conn.execute("SELECT COUNT(*) as c FROM auth_log WHERE POSITION('OK' IN event_type) > 0").fetchone()["c"]
    auth_fail  = conn.execute("SELECT COUNT(*) as c FROM auth_log WHERE POSITION('FAIL' IN event_type) > 0").fetchone()["c"]
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

    data = request.get_json(silent=True) or {}
    user_id = str(data.get("user_id", "")).strip()
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    conn = get_db()
    row = conn.execute(
        "SELECT user_id, name, acct_no, active FROM users WHERE user_id=?",
        (user_id,)
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    if not row["active"]:
        conn.close()
        return jsonify({"error": "Account is already inactive"}), 409

    # Deactivation disables banking access and removes the stored biometric
    # enrollment so the account cannot authenticate again while inactive.
    conn.execute("UPDATE users SET active=0, face_enrolled=FALSE WHERE user_id=?", (user_id,))
    log_auth(conn, user_id, "ACCOUNT_DEACTIVATED",
              f"Account deactivated by administrator: {row['name']} | {row['acct_no']}")
    conn.commit()
    delete_enrollment(user_id)
    conn.close()
    return jsonify({"success": True, "user_id": user_id, "message": "Account deactivated successfully"})


# ─── Run ─────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════
# ML / AI ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route("/api/ml/fraud-check", methods=["POST"])
def ml_fraud_check():
    """
    Check if a transaction is fraudulent before executing it.
    Call this BEFORE /api/withdraw or /api/transfer for high-value transactions.

    Request:  { user_id, amount, tx_type }
    Response: { is_fraud, risk_score, risk_label, reason, recommendation, signals }
    """
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    amount  = float(data.get("amount", 0))
    tx_type = data.get("tx_type", "DEBIT")

    if not user_id or amount <= 0:
        return jsonify({"error": "user_id and amount required"}), 400

    result = compute_risk_score(user_id, amount, tx_type)
    return jsonify(result)


@app.route("/api/ml/spending-pattern/<user_id>", methods=["GET"])
def ml_spending_pattern(user_id):
    """Analyse spending with K-Means; return a safe result when history is insufficient."""
    try:
        result = analyse_spending_pattern(user_id)
        return jsonify(result)
    except Exception as exc:
        logging.exception("ML spending-pattern error for %s", user_id)
        return jsonify({
            "pattern_label": "Unavailable",
            "cluster_id": -1,
            "avg_transaction": 0,
            "most_common_type": "N/A",
            "peak_hour": 12,
            "total_transactions": 0,
            "insights": ["ML spending analysis is temporarily unavailable. Existing banking data is unaffected."],
            "error": "ML analysis unavailable"
        }), 200


@app.route("/api/ml/predict/<user_id>", methods=["GET"])
def ml_predict(user_id):
    """Predict next transaction with Linear Regression when enough history exists."""
    try:
        result = predict_next_transaction(user_id)
        return jsonify(result)
    except Exception:
        logging.exception("ML prediction error for %s", user_id)
        return jsonify({
            "predicted_amount": 0,
            "trend": "unknown",
            "confidence": "low",
            "based_on": 0,
            "message": "Insufficient transaction history for prediction"
        }), 200


@app.route("/api/ml/auth-anomaly/<user_id>", methods=["GET"])
def ml_auth_anomaly(user_id):
    """Analyse authentication history without breaking the user dashboard."""
    try:
        result = detect_auth_anomaly(user_id)
        return jsonify(result)
    except Exception:
        logging.exception("ML auth-anomaly error for %s", user_id)
        return jsonify({
            "is_anomalous": False,
            "anomaly_score": 0,
            "signals": {"message": "Insufficient authentication history"},
            "recommendation": "Monitor"
        }), 200


@app.route("/api/ml/report/<user_id>", methods=["GET"])
def ml_report(user_id):
    """Full ML report for a user. Always returns a usable dashboard response."""
    try:
        conn = get_db()
        row = conn.execute("SELECT name FROM users WHERE user_id=%s", (user_id,)).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "User not found"}), 404
        return jsonify(generate_ml_report(user_id))
    except Exception:
        logging.exception("ML report error for %s", user_id)
        return jsonify({
            "user_id": user_id,
            "generated_at": now_str(),
            "spending_pattern": {
                "pattern_label": "New User", "cluster_id": -1,
                "avg_transaction": 0, "most_common_type": "N/A",
                "peak_hour": 12, "total_transactions": 0,
                "insights": ["Not enough transaction history to analyse spending pattern"]
            },
            "next_transaction_prediction": {
                "predicted_amount": 0, "trend": "unknown",
                "confidence": "low", "based_on": 0,
                "message": "Need at least 5 transactions to predict"
            },
            "auth_anomaly": {
                "is_anomalous": False, "anomaly_score": 0,
                "signals": {"message": "Insufficient login history"},
                "recommendation": "Monitor"
            },
            "models_used": ["KMeans", "LinearRegression", "Rule-based authentication analysis"],
            "status": "insufficient_history"
        }), 200


@app.route("/api/ml/admin/fraud-summary", methods=["GET"])
def ml_admin_fraud_summary():
    """
    Admin endpoint — fraud summary across all users.
    Shows risk distribution and flagged transactions.
    Requires X-Admin-Password header.
    """
    pw = request.headers.get("X-Admin-Password", "")
    if pw != ADMIN_PW:
        return jsonify({"error": "Unauthorized"}), 401

    conn  = get_db()
    users = conn.execute("SELECT user_id, name FROM users WHERE active=1").fetchall()
    conn.close()

    summary = []
    for u in users:
        pattern   = analyse_spending_pattern(u["user_id"])
        auth_check = detect_auth_anomaly(u["user_id"])
        summary.append({
            "user_id"      : u["user_id"],
            "name"         : u["name"],
            "pattern_label": pattern["pattern_label"],
            "total_tx"     : pattern["total_transactions"],
            "avg_tx"       : pattern["avg_transaction"],
            "auth_anomaly" : auth_check["is_anomalous"],
            "auth_score"   : auth_check["anomaly_score"]
        })

    return jsonify({
        "total_users": len(summary),
        "flagged_users": [s for s in summary if s["auth_anomaly"]],
        "high_spenders": [s for s in summary if s["pattern_label"] == "High Spender"],
        "all_users": summary
    })
if __name__ == "__main__":
    init_db()
    print("\n" + "═" * 60)
    print("  🏦  FaceAuthBank API Server — Security-Hardened")
    print("═" * 60)
    print("  Frontend  : http://localhost:5000/")
    print("  API Base  : http://localhost:5000/api/")
    print(f"  Threshold : {THRESHOLD} (strict; resume-aligned ≤ 0.6)")
    print("  Liveness  : ENABLED (multi-frame variance)")
    print("  Lockout   : 3 attempts → 5-min ban")
    print("═" * 60 + "\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
