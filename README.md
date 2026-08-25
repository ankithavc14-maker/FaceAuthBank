````markdown
# FaceAuthBank — Biometric Banking System

A production-style banking application secured with **face authentication, multi-frame liveness verification, biometric transaction confirmation, PostgreSQL, audit logging, and machine-learning insights**.

🔗 **Live Demo:** https://faceauthbank.onrender.com/  
🔗 **GitHub:** https://github.com/ankithavc14-maker/FaceAuthBank

---

## 🚀 Overview

FaceAuthBank is a full-stack biometric banking system built with Flask and PostgreSQL.

Instead of relying only on traditional passwords, the system uses **facial biometrics and liveness verification** to authenticate users and authorize sensitive banking operations.

The application includes both a **customer banking interface** and an **administrator dashboard**, together with ML-powered analytics for detecting unusual activity and analyzing transaction patterns.

---

## ✨ Key Features

### 🔐 Biometric Authentication
- Face-based user authentication
- 128-dimensional facial embeddings
- Multi-frame liveness verification
- Biometric confirmation for sensitive transactions
- Failed authentication tracking
- Temporary login lockout after repeated failed attempts

### 🏦 Banking Operations
- Account registration
- Deposit
- Withdrawal
- Transfer
- NEFT
- Fixed Deposit (FD)
- Recurring Deposit (RD)
- Transaction history
- Account balance tracking
- Transaction reference numbers

### 👤 User Management
- User profile information
- Account details
- Face registration for existing accounts
- Profile image support
- Account activation/deactivation handling

### 🛡️ Admin Dashboard
- View registered users
- View account information
- Deactivate accounts
- View transactions
- View authentication logs
- Security monitoring
- ML-powered insights

---

## 🤖 Machine Learning

FaceAuthBank includes a dedicated ML analytics layer using **scikit-learn**.

### Isolation Forest
Used for **anomaly detection** to identify unusual authentication or transaction activity.

### K-Means
Used for **behavior/activity clustering** to group transaction patterns.

### Linear Regression
Used for **trend analysis and prediction** based on available transaction and balance data.

The ML insights are available through the user and administrator dashboards.

---

## 📷 Face Recognition Pipeline

```text
Camera
   ↓
Face Detection
   ↓
Face Encoding
   ↓
128-D Embedding
   ↓
Liveness Verification
   ↓
Similarity Comparison
   ↓
Authentication / Transaction Authorization
````

The system uses OpenCV and `face_recognition`/dlib for computer-vision processing and facial embeddings.

---

## 🔒 Security

* Biometric authentication
* Multi-frame liveness checking
* Transaction-level face verification
* Authentication attempt logging
* Temporary lockout after repeated failures
* Admin authentication
* Audit trail for transactions and authentication events
* Unique transaction reference numbers
* Account activation/deactivation controls

> This project is intended as an educational/portfolio demonstration of biometric banking architecture and should not be used as a real financial banking system without additional security, compliance, infrastructure, and operational controls.

---

## 🧠 Technology Stack

| Layer                | Technology              |
| -------------------- | ----------------------- |
| Backend              | Python, Flask           |
| Database             | PostgreSQL              |
| Database Hosting     | Neon                    |
| Computer Vision      | OpenCV                  |
| Face Recognition     | face_recognition, dlib  |
| Machine Learning     | scikit-learn            |
| Numerical Processing | NumPy                   |
| Image Processing     | Pillow                  |
| API                  | REST / JSON             |
| Frontend             | HTML5, CSS3, JavaScript |
| Deployment           | Render                  |
| Version Control      | Git / GitHub            |

---

## 📁 Project Structure

```text
FaceAuthBank/
│
├── app.py
├── db.py
├── face_engine.py
├── ml_engine.py
├── authenticate_user.py
├── register_user.py
├── enroll_user.py
├── admin_dashboard.py
├── performance_analysis.py
│
├── index.html
├── requirements.txt
├── schema.sql
├── render.yaml
├── build_render.sh
│
├── face_data/
├── bank_log.txt
│
└── README.md
```

---

## ⚙️ Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/ankithavc14-maker/FaceAuthBank.git
cd FaceAuthBank
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure PostgreSQL

Set your database connection string:

```text
DATABASE_URL=postgresql://username:password@host:port/database?sslmode=require
```

### 5. Start the application

```bash
python app.py
```

Open:

```text
http://localhost:5000
```

---

## 🌐 Production Deployment

Current deployment:

```text
FaceAuthBank
      ↓
Render
      ↓
Flask API
      ↓
Neon PostgreSQL
```

Live application:

[https://faceauthbank.onrender.com/](https://faceauthbank.onrender.com/)

---

## 🔌 API

Example API areas include:

```text
/api/users
/api/login
/api/register
/api/transactions
/api/admin/*
/api/ml/*
```

The frontend communicates with the Flask API through relative production API paths.

---

## 📊 ML & Security Insights

The dashboards can provide:

* Authentication activity
* Transaction behavior
* Suspicious activity
* Transaction trends
* User activity patterns
* Anomaly scores
* ML-generated reports

---

## 🎯 Project Highlights

* Full-stack biometric banking workflow
* Real face recognition
* Multi-frame liveness verification
* PostgreSQL-backed persistence
* Transaction-level biometric authorization
* Admin security controls
* Machine-learning analytics
* REST API architecture
* Production deployment

---

## 🔗 Links

**Live Demo:**
[https://faceauthbank.onrender.com/](https://faceauthbank.onrender.com/)

**GitHub Repository:**
[https://github.com/ankithavc14-maker/FaceAuthBank](https://github.com/ankithavc14-maker/FaceAuthBank)

---

## 👩‍💻 Author

**Ankitha V Chandan**

AI/ML Engineer · Backend Developer

**GitHub:**
[https://github.com/ankithavc14-maker](https://github.com/ankithavc14-maker)

**LinkedIn:**
[https://www.linkedin.com/in/ankitha-chandan-03a82b411](https://www.linkedin.com/in/ankitha-chandan-03a82b411)

---

## 📌 Disclaimer

FaceAuthBank is a **college/portfolio project demonstrating biometric authentication, banking workflows, backend engineering, and machine-learning concepts**.

It is not intended for processing real financial transactions or storing real banking/biometric data in a production financial environment.

```
```
