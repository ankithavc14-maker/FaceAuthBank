"""
FaceAuthBank - Face Authentication + Banking Transactions
Every transaction requires a fresh face scan.
"""
import cv2
import face_recognition
import numpy as np
import sqlite3
import logging
import uuid
from datetime import datetime

FACE_DIR = "face_data"
DB_FILE  = "face_auth_bank.db"
LOG_FILE = "bank_log.txt"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s - %(message)s")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def load_encoding(user_id: str):
    import os
    path = f"{FACE_DIR}/{user_id}.npy"
    if not os.path.exists(path):
        return None
    try:
        return np.load(path)
    except Exception as e:
        print(f"❌ Error loading encoding: {e}")
        return None

def scan_face(user_id: str, prompt: str = "Face Scan") -> bool:
    """Scan face from webcam and compare against stored encoding."""
    encoding = load_encoding(user_id)
    if encoding is None:
        print("❌ Face encoding not found. Please re-enroll.")
        return False

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("❌ Camera not available.")
        return False

    print(f"\n📷 {prompt} — Look at the camera. Press 'Q' to cancel.")
    result = False
    attempts = 0

    while attempts < 60:  # ~5 seconds at 12fps
        ret, frame = cap.read()
        if not ret:
            break
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs = face_recognition.face_locations(rgb)
        encs = face_recognition.face_encodings(rgb, locs)

        for enc in encs:
            matches = face_recognition.compare_faces([encoding], enc, tolerance=0.5)
            dist = face_recognition.face_distance([encoding], enc)[0]
            if matches[0]:
                cv2.putText(frame, f"✅ Verified ({1-dist:.0%})", (10, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 120), 2)
                cv2.imshow("FaceAuthBank - Authentication", frame)
                cv2.waitKey(800)
                result = True
                cap.release()
                cv2.destroyAllWindows()
                return True

        for (top, right, bottom, left) in locs:
            cv2.rectangle(frame, (left, top), (right, bottom), (255, 180, 0), 2)

        cv2.putText(frame, f"Scanning... | Q=Cancel", (10, 30),
            cv2.FONT_HERSHEY_SIMPLEX, 0.65, (200, 200, 200), 2)
        cv2.imshow("FaceAuthBank - Authentication", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
        attempts += 1

    cap.release()
    cv2.destroyAllWindows()
    return False

def log_auth(conn, user_id: str, event: str, msg: str):
    conn.execute(
        "INSERT INTO auth_log (user_id, event_type, message, timestamp) VALUES (?,?,?,?)",
        (user_id, event, msg, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    logging.info(f"[{event}] {msg}")

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
    if not scan_face(user['user_id'], f"Confirm Deposit ₹{amount:,.2f}"):
        print("❌ Authentication failed. Transaction cancelled.")
        log_auth(conn, user['user_id'], "TX_FAIL", f"Deposit ₹{amount} — auth failed")
        return

    new_bal = user['balance'] + amount
    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal, user['user_id']))
    conn.commit()
    ref = record_tx(conn, user['user_id'], "CREDIT", amount, "Cash Deposit", new_bal)
    log_auth(conn, user['user_id'], "DEPOSIT", f"Deposited ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    print(f"\n✅ Deposited ₹{amount:,.2f} | New Balance: ₹{new_bal:,.2f} | Ref: {ref}")
    user['balance'] = new_bal

def do_withdraw(conn, user):
    try:
        amount = float(input("Enter withdrawal amount (₹): "))
    except ValueError:
        print("❌ Invalid amount."); return
    if amount <= 0:
        print("❌ Amount must be positive."); return
    if amount > user['balance']:
        print(f"❌ Insufficient funds. Balance: ₹{user['balance']:,.2f}"); return
    if amount > 50000:
        print("❌ Max ₹50,000 per transaction."); return

    print(f"\n🔐 Face scan required to withdraw ₹{amount:,.2f}")
    if not scan_face(user['user_id'], f"Confirm Withdrawal ₹{amount:,.2f}"):
        print("❌ Authentication failed. Transaction cancelled.")
        log_auth(conn, user['user_id'], "TX_FAIL", f"Withdrawal ₹{amount} — auth failed")
        return

    new_bal = user['balance'] - amount
    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal, user['user_id']))
    conn.commit()
    ref = record_tx(conn, user['user_id'], "DEBIT", amount, "Cash Withdrawal", new_bal)
    log_auth(conn, user['user_id'], "WITHDRAWAL", f"Withdrew ₹{amount} | Bal: ₹{new_bal} | Ref: {ref}")
    print(f"\n✅ Withdrew ₹{amount:,.2f} | New Balance: ₹{new_bal:,.2f} | Ref: {ref}")
    user['balance'] = new_bal

def do_transfer(conn, user):
    users = list_users(conn)
    others = [u for u in users if u['user_id'] != user['user_id']]
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
    if amount <= 0:
        print("❌ Amount must be positive."); return
    if amount > user['balance']:
        print(f"❌ Insufficient funds. Balance: ₹{user['balance']:,.2f}"); return

    print(f"\n🔐 Face scan required to transfer ₹{amount:,.2f} to {recipient['name']}")
    if not scan_face(user['user_id'], f"Confirm Transfer ₹{amount:,.2f}"):
        print("❌ Authentication failed. Transaction cancelled.")
        log_auth(conn, user['user_id'], "TX_FAIL", f"Transfer ₹{amount} — auth failed")
        return

    new_bal_sender    = user['balance'] - amount
    new_bal_recipient = recipient['balance'] + amount

    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal_sender, user['user_id']))
    conn.execute("UPDATE users SET balance=? WHERE user_id=?", (new_bal_recipient, recipient['user_id']))
    conn.commit()

    ref = record_tx(conn, user['user_id'], "TRANSFER_OUT", amount,
                    f"Transfer to {recipient['name']} ({recipient['acct_no']})", new_bal_sender)
    record_tx(conn, recipient['user_id'], "TRANSFER_IN", amount,
              f"Transfer from {user['name']}", new_bal_recipient)

    log_auth(conn, user['user_id'], "TRANSFER", f"Sent ₹{amount} to {recipient['name']} | Ref: {ref}")
    print(f"\n✅ Transferred ₹{amount:,.2f} to {recipient['name']} | Your Balance: ₹{new_bal_sender:,.2f} | Ref: {ref}")
    user['balance'] = new_bal_sender

def do_view_history(conn, user):
    rows = conn.execute("""
        SELECT * FROM transactions WHERE user_id=?
        ORDER BY timestamp DESC LIMIT 20
    """, (user['user_id'],)).fetchall()
    if not rows:
        print("No transactions on record."); return
    print(f"\n── Transaction History: {user['name']} ──")
    print(f"{'Date/Time':<22} {'Type':<15} {'Amount':>12} {'Balance':>12}  Description")
    print("─" * 85)
    for r in rows:
        sign = "+" if r['tx_type'] in ("CREDIT","TRANSFER_IN") else "−"
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
            log_auth(conn, user['user_id'], "LOGOUT", f"Logout: {user['name']}")
            print("👋 Logged out. Goodbye!")
            break
        else:
            print("❌ Invalid choice.")

def main():
    from register_user import init_db
    init_db()

    conn = get_db()
    users = list_users(conn)
    if not users:
        print("❌ No registered users. Run register_user.py first.")
        conn.close()
        return

    print("\n═══ FACEAUTH BANK — LOGIN ═══")
    print("Registered accounts:")
    for i, u in enumerate(users, 1):
        print(f"  {i}. {u['name']} — {u['acct_no']} ({u['acct_type']})")

    try:
        choice = int(input("\nSelect account [number]: ")) - 1
        if choice < 0 or choice >= len(users): raise ValueError()
    except (ValueError, IndexError):
        print("❌ Invalid selection."); conn.close(); return

    selected = users[choice]
    user_id  = selected['user_id']

    print(f"\n🔐 Face authentication for {selected['name']}...")
    if not scan_face(user_id, f"Login — {selected['name']}"):
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
