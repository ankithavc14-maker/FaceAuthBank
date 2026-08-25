# FaceAuthBanking

PostgreSQL-backed biometric banking prototype with Flask, OpenCV, face_recognition/dlib and ML analytics.

## Important fixes in this version

- PostgreSQL via `psycopg`
- `.env` configuration
- Registration captures and checks the face **before creating an account**
- Duplicate face detection across existing embeddings
- Failed face enrollment does not leave an orphan account
- Face enrollment uses original RGB frames first, with enhanced/upsampled fallbacks
- Liveness check and brute-force lockout
- Login requires a real face enrollment; demo-mode login is removed
- Successful face verification issues a short-lived, one-time server token
- Financial transaction endpoints no longer trust `face_ok=true` from the browser
- Admin APIs return JSON errors instead of HTML 500 pages
- Runtime secrets and biometric files are excluded from the distribution

## Setup

Create `.env` beside `app.py`:

```env
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/faceauthbank
FACEAUTH_ADMIN_PW=change-this-admin-password
```

Create the PostgreSQL database `faceauthbank`, then:

```powershell
python -m pip install -r requirements.txt
python -c "from db import init_db; init_db()"
python app.py
```

Open `http://127.0.0.1:5000`.

## Notes

This is a project/demo banking system, not a production banking application. Face embeddings are still stored as local `.npy` files for compatibility with the existing project. A production deployment should encrypt biometric data, use a proper secrets manager, HTTPS, strong admin authentication, database transactions/locking, rate limiting, audit controls, and a dedicated anti-spoofing model.
