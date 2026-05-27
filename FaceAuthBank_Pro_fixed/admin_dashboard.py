"""
FaceAuthBank - Admin Dashboard (Terminal)
View all users, all transactions, auth logs, and manage accounts.
"""
import sqlite3
from datetime import datetime

DB_FILE = "face_auth_bank.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def sep(char="═", n=70): print(char * n)

def show_all_users(conn):
    rows = conn.execute("""
        SELECT u.user_id, u.name, u.acct_no, u.acct_type, u.balance,
               u.email, u.phone, u.created_at,
               COUNT(t.tx_id) as tx_count
        FROM users u
        LEFT JOIN transactions t ON u.user_id = t.user_id
        WHERE u.active=1
        GROUP BY u.user_id
        ORDER BY u.created_at DESC
    """).fetchall()

    sep()
    print(f"  ALL REGISTERED USERS  ({len(rows)} total)")
    sep()
    if not rows:
        print("  No users registered yet."); return

    print(f"  {'Name':<20} {'Acct No.':<15} {'Type':<10} {'Balance':>12}  {'Txns':>5}  {'Registered'}")
    print("  " + "─" * 78)
    total_bal = 0
    for r in rows:
        total_bal += r['balance']
        print(f"  {r['name']:<20} {r['acct_no']:<15} {r['acct_type']:<10} ₹{r['balance']:>10,.2f}  {r['tx_count']:>5}  {r['created_at'][:16]}")
    print("  " + "─" * 78)
    print(f"  {'TOTAL SYSTEM BALANCE':<47} ₹{total_bal:>10,.2f}")

def show_all_transactions(conn):
    rows = conn.execute("""
        SELECT t.*, u.name
        FROM transactions t
        JOIN users u ON t.user_id = u.user_id
        ORDER BY t.timestamp DESC
        LIMIT 50
    """).fetchall()

    sep()
    print(f"  ALL TRANSACTIONS  (latest 50)")
    sep()
    if not rows:
        print("  No transactions yet."); return

    print(f"  {'Timestamp':<20} {'User':<18} {'Type':<16} {'Amount':>12} {'Balance':>12}  Ref")
    print("  " + "─" * 88)
    for r in rows:
        sign = "+" if r['tx_type'] in ("CREDIT","TRANSFER_IN") else "−"
        print(f"  {r['timestamp'][:19]:<20} {r['name']:<18} {r['tx_type']:<16} "
              f"{sign}₹{r['amount']:>9,.2f} ₹{r['balance_after']:>9,.2f}  {r['ref_no']}")

def show_auth_logs(conn):
    rows = conn.execute("""
        SELECT a.*, u.name
        FROM auth_log a
        LEFT JOIN users u ON a.user_id = u.user_id
        ORDER BY a.timestamp DESC
        LIMIT 40
    """).fetchall()

    sep()
    print("  AUTHENTICATION & SECURITY LOGS  (latest 40)")
    sep()
    if not rows:
        print("  No logs yet."); return

    for r in rows:
        name = r['name'] or "Unknown"
        tag  = "✅" if "OK" in r['event_type'] or r['event_type']=="DEPOSIT" or r['event_type']=="ENROLL" else \
               "❌" if "FAIL" in r['event_type'] else "ℹ️ "
        print(f"  {tag} [{r['timestamp'][:19]}] {r['event_type']:<14}  {name:<20}  {r['message']}")

def show_summary(conn):
    stats = conn.execute("""
        SELECT
            COUNT(DISTINCT user_id) AS users,
            SUM(CASE WHEN tx_type='CREDIT' THEN amount ELSE 0 END) AS deposits,
            SUM(CASE WHEN tx_type='DEBIT'  THEN amount ELSE 0 END) AS withdrawals,
            SUM(CASE WHEN tx_type='TRANSFER_OUT' THEN amount ELSE 0 END) AS transfers,
            COUNT(*) AS total_tx
        FROM transactions
    """).fetchone()

    total_bal = conn.execute("SELECT SUM(balance) FROM users WHERE active=1").fetchone()[0] or 0
    auth_ok   = conn.execute("SELECT COUNT(*) FROM auth_log WHERE event_type LIKE '%OK%'").fetchone()[0]
    auth_fail = conn.execute("SELECT COUNT(*) FROM auth_log WHERE event_type LIKE '%FAIL%'").fetchone()[0]

    sep()
    print("  SYSTEM SUMMARY")
    sep()
    print(f"  Total Registered Users     : {stats['users']}")
    print(f"  Total System Balance       : ₹{total_bal:,.2f}")
    print(f"  Total Transactions         : {stats['total_tx']}")
    print(f"  Total Deposits (CREDIT)    : ₹{(stats['deposits'] or 0):,.2f}")
    print(f"  Total Withdrawals (DEBIT)  : ₹{(stats['withdrawals'] or 0):,.2f}")
    print(f"  Total Transfers            : ₹{(stats['transfers'] or 0):,.2f}")
    print(f"  Auth Success               : {auth_ok}")
    print(f"  Auth Failures              : {auth_fail}")

def deactivate_user(conn):
    rows = conn.execute("SELECT user_id, name, acct_no FROM users WHERE active=1").fetchall()
    if not rows:
        print("  No active users."); return
    for i, r in enumerate(rows, 1):
        print(f"  {i}. {r['name']} — {r['acct_no']}")
    try:
        c = int(input("  Select user to deactivate: ")) - 1
        uid = rows[c]['user_id']
        name = rows[c]['name']
        confirm = input(f"  Deactivate {name}? (yes/no): ").strip().lower()
        if confirm == "yes":
            conn.execute("UPDATE users SET active=0 WHERE user_id=?", (uid,))
            conn.commit()
            print(f"  ✅ {name} deactivated.")
    except (ValueError, IndexError):
        print("  Invalid selection.")

ADMIN_PASSWORD = "admin123"

def admin_menu():
    try:
        conn = get_db()
    except Exception as e:
        print(f"❌ DB error: {e}"); return

    sep()
    print("  FACEAUTH BANK — ADMIN DASHBOARD")
    sep()
    pwd = input("  Enter admin password: ")
    if pwd != ADMIN_PASSWORD:
        print("❌ Wrong password."); conn.close(); return

    MENU = """
╔═══════════════════════════════╗
║  FACEAUTH BANK — ADMIN MENU   ║
╠═══════════════════════════════╣
║  1. System Summary            ║
║  2. All Users                 ║
║  3. All Transactions          ║
║  4. Auth / Security Logs      ║
║  5. Deactivate User           ║
║  6. Exit                      ║
╚═══════════════════════════════╝"""

    while True:
        print(MENU)
        choice = input("  Choice: ").strip()
        if   choice == "1": show_summary(conn)
        elif choice == "2": show_all_users(conn)
        elif choice == "3": show_all_transactions(conn)
        elif choice == "4": show_auth_logs(conn)
        elif choice == "5": deactivate_user(conn)
        elif choice == "6": print("  Goodbye, Admin."); break
        else: print("  ❌ Invalid choice.")

    conn.close()

if __name__ == "__main__":
    admin_menu()
