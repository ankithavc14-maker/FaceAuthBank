BANKING SYSTEMZZ - FACEAUTH BANK

This is the complete project in a single folder.

MAIN FEATURES
- Flask banking backend
- PostgreSQL database
- Face recognition authentication
- Liveness / live face verification
- Duplicate face prevention
- User registration and login
- Deposits, withdrawals and transfers
- Transaction history
- Admin dashboard and security logs
- Delete/deactivate account functionality
- ML transaction analysis (see ml_engine.py)
- Modern dark-blue/cyan UI
- UI transitions, hover effects and biometric animations

RUN
1. Open PowerShell in this folder.
2. Create/activate your Python environment if needed.
3. Install dependencies:
   python -m pip install -r requirements.txt
4. Configure your database and environment variables using .env.example.
5. Start:
   python app.py
6. Open:
   http://127.0.0.1:5000

IMPORTANT
Do not open index.html directly with file://. The browser must load it through Flask.
