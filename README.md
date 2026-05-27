# FaceAuthBank — Biometric Banking System

A real banking system secured by face recognition.  
Every transaction requires a live face scan for authentication.

---

## Project Structure

```
FaceAuthBank_Pro/
├── index.html            ← Full-featured web frontend (open in browser)
├── register_user.py      ← CLI: Register new user + enroll face
├── authenticate_user.py  ← CLI: Login + all banking transactions
├── admin_dashboard.py    ← CLI: Admin — all users & transactions
├── face_data/            ← Stores face encodings (.npy per user)
├── face_auth_bank.db     ← SQLite database (users, transactions, logs)
├── bank_log.txt          ← Audit log file
└── requirements.txt      ← Python dependencies
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```
> Note: `dlib` requires CMake. On Ubuntu: `sudo apt install cmake build-essential`

### 2. Run the web frontend
Just open `index.html` in any browser — no server needed.

### 3. Register a new user (Python CLI)
```bash
python register_user.py
```
- Enter name, email, phone, address, ID proof, nominee
- Webcam opens — look at camera, press **S** to save face
- Account created with ₹0 balance

### 4. Login & do transactions (Python CLI)
```bash
python authenticate_user.py
```
- Select your account
- Face scan to login
- Every transaction (deposit/withdraw/transfer) requires another face scan

### 5. Admin dashboard (Python CLI)
```bash
python admin_dashboard.py
```
- Password: `admin123`
- View all users, all transactions, security logs

---

## Features

### Web Frontend (`index.html`)
- Register with name + simulated face capture
- Login with face scan simulation (90% success rate)
- **Every transaction** triggers a face verification modal
- Full banking: Deposit, Withdraw, Transfer, NEFT, Cheque, FD, RD, Loan
- Virtual debit card generation
- Admin panel: all users + all transactions + auth logs
- Transaction history, mini statement, activity chart
- Profile page with account details

### Python Backend
- Real webcam face capture using `face_recognition` + `opencv-python`
- 128-D face encoding stored as `.npy` files
- SQLite database for users, transactions, and auth logs
- Per-transaction biometric confirmation
- Max ₹50,000 per withdrawal
- Full audit trail in `bank_log.txt`

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Face Detection | OpenCV (cv2) |
| Face Recognition | face_recognition (dlib) |
| Encoding Storage | NumPy (.npy files) |
| Database | SQLite 3 |
| Frontend | HTML5 + CSS3 + Vanilla JS |
| Logging | Python logging module |

---

## Security Features

- Zero-password authentication — biometrics only
- Every single transaction requires fresh face scan
- Euclidean distance comparison with tolerance 0.5
- Failed auth attempts logged with timestamp
- Admin sees all auth events across all users
- Transaction reference numbers for every operation

---

*Developed as a college project demonstrating biometric banking security.*
