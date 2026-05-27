"""
FaceAuthBank - Real-Time User Registration
Captures face via webcam, saves 128-D encoding to face_data/<user_id>.npy
and stores account info in face_auth_bank.db
"""
import cv2
import face_recognition
import numpy as np
import os
import sqlite3
import logging
import uuid
import random
from datetime import datetime

FACE_DIR = "face_data"
DB_FILE  = "face_auth_bank.db"
LOG_FILE = "bank_log.txt"

os.makedirs(FACE_DIR, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s - %(message)s")

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
            email       TEXT UNIQUE,
            phone       TEXT,
            acct_no     TEXT UNIQUE,
            acct_type   TEXT DEFAULT 'savings',
            balance     REAL DEFAULT 0.0,
            id_type     TEXT,
            id_number   TEXT,
            nominee     TEXT,
            address     TEXT,
            created_at  TEXT,
            active      INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id       TEXT PRIMARY KEY,
            user_id     TEXT,
            tx_type     TEXT,
            amount      REAL,
            description TEXT,
            balance_after REAL,
            ref_no      TEXT,
            timestamp   TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS auth_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT,
            event_type  TEXT,
            message     TEXT,
            timestamp   TEXT
        );
    """)
    conn.commit()
    conn.close()

def generate_acct_no():
    return "520" + str(random.randint(1_000_000_000, 9_999_999_999))

def capture_face(user_id: str) -> bool:
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("❌ Could not open webcam.")
        return False

    print("\n📷 Webcam open. Look at the camera.")
    print("   Press 'S' to capture face | 'Q' to cancel\n")
    saved = False

    while True:
        ret, frame = cap.read()
        if not ret:
            print("❌ Failed to read from webcam.")
            break

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs = face_recognition.face_locations(rgb)

        for (top, right, bottom, left) in locs:
            cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 120), 2)
            cv2.putText(frame, "Face Detected", (left, top - 10),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 120), 2)

        status = f"Faces: {len(locs)} | S=Save  Q=Cancel"
        cv2.putText(frame, status, (10, 30),
            cv2.FONT_HERSHEY_SIMPLEX, 0.65, (255, 255, 0), 2)
        cv2.imshow("FaceAuthBank — Face Enrollment", frame)

        key = cv2.waitKey(1) & 0xFF
        if key == ord('s') or key == ord('S'):
            if locs:
                encodings = face_recognition.face_encodings(rgb, locs)
                if encodings:
                    path = os.path.join(FACE_DIR, f"{user_id}.npy")
                    np.save(path, encodings[0])
                    print(f"\n✅ Face encoding saved to {path}")
                    saved = True
                    break
            else:
                print("⚠️  No face detected. Try again.")
        elif key == ord('q') or key == ord('Q'):
            print("👋 Enrollment cancelled.")
            break

    cap.release()
    cv2.destroyAllWindows()
    return saved

def register():
    init_db()
    print("=" * 55)
    print("      FACEAUTH BANK — USER REGISTRATION")
    print("=" * 55)

    name = input("Full Name              : ").strip()
    if not name:
        print("❌ Name is required."); return

    email = input("Email Address          : ").strip()
    phone = input("Phone Number (10 digit): ").strip()
    address = input("Address                : ").strip()

    print("\nAccount Type:")
    print("  1. Savings Account")
    print("  2. Current Account")
    print("  3. Salary Account")
    ac_choice = input("Choice [1/2/3]: ").strip()
    acct_types = {"1": "savings", "2": "current", "3": "salary"}
    acct_type = acct_types.get(ac_choice, "savings")

    print("\nID Proof:")
    print("  1. Aadhaar Card  2. PAN Card  3. Passport  4. Voter ID")
    id_choice = input("Choice [1-4]: ").strip()
    id_types = {"1":"Aadhaar Card","2":"PAN Card","3":"Passport","4":"Voter ID"}
    id_type = id_types.get(id_choice, "Aadhaar Card")
    id_number = input(f"{id_type} Number : ").strip()

    nominee = input("Nominee Name           : ").strip()

    user_id = "U" + uuid.uuid4().hex[:8].upper()
    acct_no = generate_acct_no()

    print(f"\n── Face Capture for {name} ──")
    if not capture_face(user_id):
        print("❌ Registration aborted (no face captured).")
        return

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO users
            (user_id, name, email, phone, acct_no, acct_type, balance,
             id_type, id_number, nominee, address, created_at, active)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
        """, (user_id, name, email, phone, acct_no, acct_type, 0.0,
              id_type, id_number, nominee, address,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

        conn.execute("""
            INSERT INTO auth_log (user_id, event_type, message, timestamp)
            VALUES (?,?,?,?)
        """, (user_id, "ENROLL", f"Face enrolled for {name}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

        logging.info(f"Registered new user: {name} | ID: {user_id} | Acct: {acct_no}")
        print("\n" + "=" * 55)
        print("✅  REGISTRATION SUCCESSFUL")
        print("=" * 55)
        print(f"  Name         : {name}")
        print(f"  User ID      : {user_id}")
        print(f"  Account No.  : {acct_no}")
        print(f"  Account Type : {acct_type.capitalize()}")
        print(f"  IFSC Code    : FAB0000001")
        print(f"  Branch       : Bengaluru Main")
        print(f"  Balance      : ₹0.00 (deposit to begin)")
        print("=" * 55)
    except sqlite3.IntegrityError as e:
        print(f"❌ Registration failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    register()
