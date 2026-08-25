"""
FaceAuthBank — CLI Authentication (Security-Hardened)
=====================================================
Security fixes:
  ✅ Liveness detection via multi-frame capture (5 frames)
  ✅ Brute-force lockout enforced (3 attempts → 5-min ban)
  ✅ Threshold aligned to 0.45 (< resume-stated 0.6)
"""
import cv2
import face_recognition
import numpy as np
import logging
import uuid
from datetime import datetime
from face_engine import (
    verify_face, has_enrollment, is_locked_out,
    record_failed_attempt, reset_failed_attempts, THRESHOLD
)

LOG_FILE = "bank_log.txt"
CAPTURE_FRAMES = 5   # Number of frames to capture for liveness check

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s - %(message)s")

from db import get_db, init_db

def log_auth(conn, user_id: str, event: str, msg: str):
    conn.execute(
        "INSERT INTO auth_log (user_id, event_type, message, timestamp) VALUES (?,?,?,?)",
        (user_id, event, msg, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    logging.info(f"[{event}] {msg}")

def capture_frames_for_liveness(prompt: str = "Face Scan") -> list[np.ndarray]:
    """
    Capture multiple frames from webcam for liveness detection.
    Returns list of BGR frames (empty list on failure).
    """
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("❌ Camera not available.")
        return []

    print(f"\n📷 {prompt}")
    print(f"   Please move your head slightly left/right during scan (liveness check).")
    print(f"   Capturing {CAPTURE_FRAMES} frames... Press 'Q' to cancel.\n")

    frames_collected = []
    attempts         = 0
    max_attempts     = 120  # ~10 seconds

    while attempts < max_attempts and len(frames_collected) < CAPTURE_FRAMES:
        ret, frame = cap.read()
        if not ret:
            break

        rgb  = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs = face_recognition.face_locations(rgb)

        status_color = (255, 180, 0)
        if locs:
            for (top, right, bottom, left) in locs:
                cv2.rectangle(frame, (left, top), (right, bottom), (0, 200, 100), 2)
            # Capture every 10th frame to ensure temporal spread
            if attempts % 10 == 0:
                frames_collected.append(frame.copy())
            status_color = (0, 200, 100)

        cv2.putText(frame,
            f"Frames: {len(frames_collected)}/{CAPTURE_FRAMES} | Move head slightly | Q=Cancel",
            (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, status_color, 2)
        cv2.imshow(f"FaceAuthBank — {prompt}", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
        attempts += 1

    cap.release()
    cv2.destroyAllWindows()
    return frames_collected


def encode_frames_to_b64(frames: list[np.ndarray]) -> list[str]:
    """Convert BGR frames to base64 strings for face_engine."""
    import base64
    encoded = []
    for frame in frames:
        _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 90])
        b64    = base64.b64encode(buf.tobytes()).decode("utf-8")
        encoded.append(b64)
    return encoded


def scan_face_secure(user_id: str, prompt: str = "Face Scan") -> bool:
    """
    Secure face scan with liveness detection + lockout enforcement.
    Returns True only if face verified AND liveness passed AND not locked out.
    """
    # Check lockout first
    locked, remaining = is_locked_out(user_id)
    if locked:
        mins = remaining // 60
        secs = remaining % 60
        print(f"\n🔒 Account locked due to too many failed attempts.")
        print(f"   Try again in {mins}m {secs}s.")
        return False

    # Capture multi-frame for liveness
    frames = capture_frames_for_liveness(prompt)
    if not frames:
        print("❌ No frames captured. Authentication cancelled.")
        return False

    if len(frames) < 3:
        print(f"❌ Only {len(frames)} frame(s) captured — need at least 3 for liveness check.")
        record_failed_attempt(user_id)
        return False

    # Convert to base64 and verify
    frames_b64 = encode_frames_to_b64(frames)
    result     = verify_face(user_id, frames_b64)

    if result["verified"]:
        dist = result["confidence"]
        qual = result.get("match_quality", "?")
        print(f"\n✅ Verified — Match quality: {qual} (distance: {dist:.3f} ≤ {THRESHOLD})")
        return True
    else:
        error    = result.get("error", "Face authentication failed")
        lockout  = result.get("lockout", {})
        attempts = lockout.get("attempts", "?")
        locked   = lockout.get("locked", False)

        print(f"\n❌ Authentication failed: {error}")
        if locked:
            remaining = lockout.get("seconds_remaining", 0)
            print(f"🔒 Account locked for {remaining // 60}m {remaining % 60}s.")
        else:
            print(f"   Attempts used: {attempts}/3")
        return False


def record_tx(conn, user_id: str, tx_type: str, amount: float,
              description: str, balance_after: float):
    ref = "REF" + uuid.uuid4().hex[:8].upper()
    conn.execute("""
        INSERT INTO transactions
        (tx_id, user_id, tx_type, amount, description, balance_after, ref_no, timestamp)
        VALUES (?,?,?,?,?,?,?,?)
    """, (uuid.uuid4().hex, user_id, tx_type, amount, description,
          balance_after, ref, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    return ref

def get_user(conn, user_id: str):
    row = conn.execute("SELECT * FROM users WHERE user_id=? AND active=1", (user_id,)).fetchone()
    return dict(row) if row else None

def list_users(conn):
    rows = conn.execute("SELECT user_id, name, acct_no, acct_type, balance FROM users WHERE active=1").fetchall()
    return [dict(r) for r in rows]

def do_deposit(conn, user):
    try:
        amount = float(input("Enter deposit amount (₹): "))
    except ValueError:
        print("❌ Invalid amount."); return
    if amount <= 0:
        print("❌ Amount must be positive."); return

    print(f"\n🔐 Face scan required to deposit ₹{amount:,.2f}")
    if not scan_face_secure(user["user_id"], f"Confirm Deposit ₹{amount:,.2f}"):
        print("❌ Authentication failed. Transaction cancelled.")
        log_auth(conn, user["user_id"], "TX_FAIL", f"Deposit ₹{amount} — auth failed")
        return

    new_bal = user["balance"] + amount
    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal, user["user_id"]))
    conn.commit()
    ref = record_tx(conn, user["user_id"], "CREDIT", amount, "Cash Deposit", new_bal)
    log_auth(conn, user["user_id"], "DEPOSIT", f"Deposited ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    print(f"\n✅ Deposited ₹{amount:,.2f} | New Balance: ₹{new_bal:,.2f} | Ref: {ref}")
    user["balance"] = new_bal

def do_withdraw(conn, user):
    try:
        amount = float(input("Enter withdrawal amount (₹): "))
    except ValueError:
        print("❌ Invalid amount."); return
    if amount <= 0:
        print("❌ Amount must be positive."); return
    if amount > user["balance"]:
        print(f"❌ Insufficient funds. Balance: ₹{user['balance']:,.2f}"); return
    if amount > 50000:
        print("❌ Max ₹50,000 per transaction."); return

    print(f"\n🔐 Face scan required to withdraw ₹{amount:,.2f}")
    if not scan_face_secure(user["user_id"], f"Confirm Withdrawal ₹{amount:,.2f}"):
        print("❌ Authentication failed. Transaction cancelled.")
        log_auth(conn, user["user_id"], "TX_FAIL", f"Withdrawal ₹{amount} — auth failed")
        return

    new_bal = user["balance"] - amount
    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal, user["user_id"]))
    conn.commit()
    ref = record_tx(conn, user["user_id"], "DEBIT", amount, "Cash Withdrawal", new_bal)
    log_auth(conn, user["user_id"], "WITHDRAWAL", f"Withdrew ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    print(f"\n✅ Withdrew ₹{amount:,.2f} | New Balance: ₹{new_bal:,.2f} | Ref: {ref}")
    user["balance"] = new_bal

def do_transfer(conn, user):
    users  = list_users(conn)
    others = [u for u in users if u["user_id"] != user["user_id"]]
    if not others:
        print("❌ No other accounts available for transfer."); return

    print("\n── Available Accounts ──")
    for i, u in enumerate(others, 1):
        print(f"  {i}. {u['name']} — Acct: {u['acct_no']}")
    try:
        choice = int(input("Select recipient [number]: ")) - 1
        if choice < 0 or choice >= len(others): raise ValueError()
    except ValueError:
        print("❌ Invalid selection."); return

    recipient = others[choice]
    try:
        amount = float(input(f"Amount to transfer to {recipient['name']} (₹): "))
    except ValueError:
        print("❌ Invalid amount."); return
    if amount <= 0 or amount > user["balance"]:
        print("❌ Invalid amount or insufficient funds."); return

    print(f"\n🔐 Face scan required to transfer ₹{amount:,.2f} to {recipient['name']}")
    if not scan_face_secure(user["user_id"], f"Confirm Transfer ₹{amount:,.2f}"):
        print("❌ Authentication failed. Transaction cancelled.")
        log_auth(conn, user["user_id"], "TX_FAIL", f"Transfer ₹{amount} — auth failed")
        return

    new_bal_s = user["balance"] - amount
    new_bal_r = recipient["balance"] + amount
    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal_s, user["user_id"]))
    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal_r, recipient["user_id"]))
    conn.commit()
    ref = record_tx(conn, user["user_id"], "TRANSFER_OUT", amount,
                    f"Transfer to {recipient['name']} ({recipient['acct_no']})", new_bal_s)
    record_tx(conn, recipient["user_id"], "TRANSFER_IN", amount,
              f"Transfer from {user['name']}", new_bal_r)
    log_auth(conn, user["user_id"], "TRANSFER", f"Sent ₹{amount} to {recipient['name']} | Ref: {ref}")
    print(f"\n✅ Transferred ₹{amount:,.2f} to {recipient['name']} | Balance: ₹{new_bal_s:,.2f} | Ref: {ref}")
    user["balance"] = new_bal_s

def do_view_history(conn, user):
    rows = conn.execute("""
        SELECT * FROM transactions WHERE user_id=?
        ORDER BY timestamp DESC LIMIT 20
    """, (user["user_id"],)).fetchall()
    if not rows:
        print("No transactions on record."); return
    print(f"\n── Transaction History: {user['name']} ──")
    print(f"{'Date/Time':<22} {'Type':<15} {'Amount':>12} {'Balance':>12}  Description")
    print("─" * 85)
    for r in rows:
        sign = "+" if r["tx_type"] in ("CREDIT", "TRANSFER_IN") else "−"
        print(f"{r['timestamp']:<22} {r['tx_type']:<15} {sign}₹{r['amount']:>10,.2f} ₹{r['balance_after']:>10,.2f}  {r['description']}")

def do_check_balance(user):
    print(f"\n  Balance: ₹{user['balance']:,.2f}")
    print(f"  Account: {user['acct_no']}  |  IFSC: FAB0000001")

def banking_menu(conn, user):
    MENU = """
╔══════════════════════════════╗
║    FACEAUTH BANK — MENU      ║
╠══════════════════════════════╣
║  1. Check Balance            ║
║  2. Deposit                  ║
║  3. Withdraw                 ║
║  4. Fund Transfer            ║
║  5. Transaction History      ║
║  6. Logout                   ║
╚══════════════════════════════╝"""
    while True:
        print(MENU)
        print(f"  Welcome, {user['name']}! Balance: ₹{user['balance']:,.2f}")
        choice = input("\n  Enter choice: ").strip()
        if   choice == "1": do_check_balance(user)
        elif choice == "2": do_deposit(conn, user)
        elif choice == "3": do_withdraw(conn, user)
        elif choice == "4": do_transfer(conn, user)
        elif choice == "5": do_view_history(conn, user)
        elif choice == "6":
            log_auth(conn, user["user_id"], "LOGOUT", f"Logout: {user['name']}")
            print("👋 Logged out. Goodbye!")
            break
        else:
            print("❌ Invalid choice.")

def main():
    from register_user import init_db
    init_db()

    conn  = get_db()
    users = list_users(conn)
    if not users:
        print("❌ No registered users. Run register_user.py first.")
        conn.close()
        return

    print("\n═══ FACEAUTH BANK — SECURE LOGIN ═══")
    print("Registered accounts:")
    for i, u in enumerate(users, 1):
        print(f"  {i}. {u['name']} — {u['acct_no']} ({u['acct_type']})")

    try:
        choice = int(input("\nSelect account [number]: ")) - 1
        if choice < 0 or choice >= len(users): raise ValueError()
    except (ValueError, IndexError):
        print("❌ Invalid selection."); conn.close(); return

    selected = users[choice]
    user_id  = selected["user_id"]

    if not has_enrollment(user_id):
        print(f"❌ No face enrolled for {selected['name']}. Please run enroll_user.py first.")
        conn.close()
        return

    print(f"\n🔐 Secure face authentication for {selected['name']}...")
    print("   (Liveness detection active — please move head slightly during scan)")

    if not scan_face_secure(user_id, f"Login — {selected['name']}"):
        log_auth(conn, user_id, "LOGIN_FAIL", f"Login failed: {selected['name']}")
        print("❌ Authentication failed. Access denied.")
        conn.close()
        return

    log_auth(conn, user_id, "LOGIN_OK", f"Login successful: {selected['name']}")
    print(f"✅ Welcome, {selected['name']}!")

    user = get_user(conn, user_id)
    banking_menu(conn, user)
    conn.close()

if __name__ == "__main__":
    main()
