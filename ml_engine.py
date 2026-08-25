"""
ml_engine.py — AI/ML Module for FaceAuthBank
=============================================
Features:
  1. Fraud Detection        — Isolation Forest flags anomalous transactions
  2. Risk Scoring           — Rule-based + ML composite risk score (0-100)
  3. Spending Pattern       — KMeans clusters user behaviour (3 types)
  4. Auth Anomaly Detection — Flags unusual login times / locations
  5. Transaction Prediction — Predicts next transaction amount (Linear Regression)

All models are trained on the fly from PostgreSQL transaction history.
No external model files needed — pure scikit-learn.
"""

import numpy as np
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

# scikit-learn imports
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler



# ─── DB helper ────────────────────────────────────────────
from db import get_db


# ══════════════════════════════════════════════════════════
# 1. FRAUD DETECTION — Isolation Forest
# ══════════════════════════════════════════════════════════

def _tx_to_features(tx: dict) -> list:
    """
    Convert a transaction dict into a numeric feature vector.
    Features:
      [0] amount
      [1] hour_of_day       (0-23)
      [2] day_of_week       (0=Mon, 6=Sun)
      [3] tx_type_encoded   (CREDIT=0, DEBIT=1, TRANSFER_OUT=2, NEFT=3, etc.)
      [4] balance_after
    """
    TYPE_MAP = {
        "CREDIT": 0, "DEBIT": 1, "TRANSFER_OUT": 2,
        "TRANSFER_IN": 3, "NEFT": 4, "FD": 5,
        "LOAN": 6, "RD": 7, "CHEQUE": 8
    }
    try:
        ts  = datetime.strptime(tx["timestamp"], "%Y-%m-%d %H:%M:%S")
        hr  = ts.hour
        dow = ts.weekday()
    except Exception:
        hr, dow = 12, 0

    return [
        float(tx.get("amount", 0)),
        hr,
        dow,
        TYPE_MAP.get(tx.get("tx_type", "DEBIT"), 1),
        float(tx.get("balance_after", 0))
    ]


def detect_fraud(user_id: str, new_tx: dict) -> dict:
    """
    Trains Isolation Forest on user's past transactions,
    then scores the new transaction.

    Returns:
      {
        is_fraud: bool,
        risk_score: float (0-100, higher = riskier),
        reason: str,
        model_used: "IsolationForest"
      }
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM transactions WHERE user_id=%s ORDER BY timestamp DESC LIMIT 200",
        (user_id,)
    ).fetchall()
    conn.close()

    history = [dict(r) for r in rows]

    # Need at least 10 transactions to train a meaningful model
    if len(history) < 10:
        return {
            "is_fraud": False,
            "risk_score": 0.0,
            "reason": "Insufficient history for ML model — rule-based checks passed",
            "model_used": "rule-based"
        }

    X = np.array([_tx_to_features(t) for t in history])
    new_x = np.array([_tx_to_features(new_tx)])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    new_scaled = scaler.transform(new_x)

    # contamination=0.05 → expects ~5% of transactions to be anomalous
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X_scaled)

    prediction = model.predict(new_scaled)[0]   # 1 = normal, -1 = anomaly
    score      = model.decision_function(new_scaled)[0]  # more negative = more anomalous

    # Normalise anomaly score to 0-100 risk scale
    # decision_function returns roughly -0.5 to 0.5; shift and scale
    risk_score = max(0, min(100, (0.5 - score) * 100))

    is_fraud = prediction == -1

    # Build human-readable reason
    amount = new_tx.get("amount", 0)
    avg_amount = np.mean([t["amount"] for t in history])
    reasons = []
    if amount > avg_amount * 3:
        reasons.append(f"Amount ₹{amount:.0f} is {amount/avg_amount:.1f}x your average ₹{avg_amount:.0f}")
    try:
        ts  = datetime.strptime(new_tx.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")), "%Y-%m-%d %H:%M:%S")
        if ts.hour < 6 or ts.hour > 23:
            reasons.append(f"Unusual transaction time: {ts.strftime('%H:%M')}")
    except Exception:
        pass
    if not reasons:
        reasons.append("ML model flagged statistical anomaly in transaction pattern")

    return {
        "is_fraud": is_fraud,
        "risk_score": round(risk_score, 1),
        "reason": " | ".join(reasons) if is_fraud else "Transaction appears normal",
        "model_used": "IsolationForest",
        "anomaly_score": round(score, 4)
    }


# ══════════════════════════════════════════════════════════
# 2. RISK SCORING — Composite Score
# ══════════════════════════════════════════════════════════

def compute_risk_score(user_id: str, tx_amount: float, tx_type: str) -> dict:
    """
    Composite risk score combining:
      - ML fraud signal (40% weight)
      - Rule-based signals (60% weight):
          * Amount vs balance ratio
          * Recent failed auth attempts
          * Transaction velocity (how many in last hour)
          * Time of day risk

    Returns score 0-100 with label: LOW / MEDIUM / HIGH / CRITICAL
    """
    conn = get_db()

    # Get user balance
    user = conn.execute(
        "SELECT balance FROM users WHERE user_id=%s", (user_id,)
    ).fetchone()
    balance = user["balance"] if user else 0

    # Recent failed auth attempts in last 30 mins
    thirty_ago = (datetime.now() - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    fail_count = conn.execute(
        "SELECT COUNT(*) as c FROM auth_log WHERE user_id=%s AND event_type LIKE '%%FAIL%%' AND timestamp > %s",
        (user_id, thirty_ago)
    ).fetchone()["c"]

    # Transaction velocity — how many transactions in last 60 mins
    one_hr_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    tx_velocity = conn.execute(
        "SELECT COUNT(*) as c FROM transactions WHERE user_id=%s AND timestamp > %s",
        (user_id, one_hr_ago)
    ).fetchone()["c"]

    conn.close()

    # ── Rule signals ──────────────────────────────────────
    rule_score = 0

    # Amount vs balance
    if balance > 0:
        ratio = tx_amount / balance
        if ratio > 0.9:
            rule_score += 40
        elif ratio > 0.7:
            rule_score += 25
        elif ratio > 0.5:
            rule_score += 10

    # Failed auth attempts
    rule_score += min(fail_count * 15, 30)

    # Transaction velocity
    if tx_velocity > 5:
        rule_score += 20
    elif tx_velocity > 3:
        rule_score += 10

    # Time of day (night transactions riskier)
    hour = datetime.now().hour
    if hour < 5 or hour >= 23:
        rule_score += 10

    rule_score = min(rule_score, 100)

    # ── ML signal ─────────────────────────────────────────
    dummy_tx = {
        "amount": tx_amount,
        "tx_type": tx_type,
        "balance_after": max(0, balance - tx_amount),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    fraud_result = detect_fraud(user_id, dummy_tx)
    ml_score = fraud_result["risk_score"]

    # ── Composite ─────────────────────────────────────────
    final_score = (rule_score * 0.6) + (ml_score * 0.4)
    final_score = round(min(final_score, 100), 1)

    if final_score >= 75:
        label = "CRITICAL"
        recommendation = "Block transaction and require manual review"
    elif final_score >= 50:
        label = "HIGH"
        recommendation = "Require additional face verification"
    elif final_score >= 25:
        label = "MEDIUM"
        recommendation = "Log and monitor"
    else:
        label = "LOW"
        recommendation = "Proceed normally"

    return {
        "risk_score": final_score,
        "risk_label": label,
        "recommendation": recommendation,
        "signals": {
            "ml_fraud_score": ml_score,
            "rule_based_score": rule_score,
            "failed_auth_attempts_30min": fail_count,
            "tx_velocity_1hr": tx_velocity,
            "amount_to_balance_ratio": round(tx_amount / balance, 2) if balance > 0 else 1.0
        },
        "is_fraud_flagged": fraud_result["is_fraud"],
        "fraud_reason": fraud_result["reason"]
    }


# ══════════════════════════════════════════════════════════
# 3. SPENDING PATTERN — KMeans Clustering
# ══════════════════════════════════════════════════════════

def analyse_spending_pattern(user_id: str) -> dict:
    """
    Clusters user's transactions into 3 spending behaviour types
    using KMeans on (amount, hour_of_day, tx_type_encoded).

    Returns:
      {
        pattern_label: "Conservative" | "Moderate" | "High Spender",
        cluster_id: int,
        avg_transaction: float,
        most_common_type: str,
        peak_hour: int,
        total_transactions: int,
        insights: [str]
      }
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM transactions WHERE user_id=%s ORDER BY timestamp DESC LIMIT 100",
        (user_id,)
    ).fetchall()
    conn.close()

    txs = [dict(r) for r in rows]

    if len(txs) < 3:
        return {
            "pattern_label": "New User",
            "cluster_id": -1,
            "avg_transaction": 0,
            "most_common_type": "N/A",
            "peak_hour": 12,
            "total_transactions": len(txs),
            "insights": ["Not enough transaction history to analyse spending pattern"]
        }

    X = np.array([_tx_to_features(t) for t in txs])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    n_clusters = min(3, len(txs))
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = kmeans.fit_predict(X_scaled)

    # Find which cluster this user's most recent tx belongs to
    user_cluster = int(labels[0])

    # Analyse cluster characteristics
    amounts = [t["amount"] for t in txs]
    avg_amount = np.mean(amounts)
    max_amount = np.max(amounts)

    # Most common transaction type
    type_counts = defaultdict(int)
    for t in txs:
        type_counts[t["tx_type"]] += 1
    most_common_type = max(type_counts, key=type_counts.get)

    # Peak hour
    hours = []
    for t in txs:
        try:
            ts = datetime.strptime(t["timestamp"], "%Y-%m-%d %H:%M:%S")
            hours.append(ts.hour)
        except Exception:
            pass
    peak_hour = int(np.bincount(hours).argmax()) if hours else 12

    # Label clusters based on avg amount
    cluster_avgs = {}
    for i, label in enumerate(labels):
        cluster_avgs.setdefault(label, []).append(txs[i]["amount"])
    cluster_mean = {k: np.mean(v) for k, v in cluster_avgs.items()}
    sorted_clusters = sorted(cluster_mean.items(), key=lambda x: x[1])

    if n_clusters >= 3:
        label_map = {
            sorted_clusters[0][0]: "Conservative",
            sorted_clusters[1][0]: "Moderate",
            sorted_clusters[2][0]: "High Spender"
        }
    elif n_clusters == 2:
        label_map = {
            sorted_clusters[0][0]: "Conservative",
            sorted_clusters[1][0]: "High Spender"
        }
    else:
        label_map = {sorted_clusters[0][0]: "Moderate"}

    pattern_label = label_map.get(user_cluster, "Moderate")

    # Generate insights
    insights = []
    if avg_amount > 10000:
        insights.append(f"Your average transaction is ₹{avg_amount:.0f} — significantly high")
    if peak_hour < 9 or peak_hour > 21:
        insights.append(f"You frequently transact at unusual hours (peak: {peak_hour}:00)")
    if most_common_type in ("TRANSFER_OUT", "NEFT"):
        insights.append("You frequently transfer money externally — monitor for unusual recipients")
    if len(txs) > 50:
        insights.append("High transaction frequency — consider setting daily limits")
    if not insights:
        insights.append("Your spending pattern looks normal and consistent")

    return {
        "pattern_label": pattern_label,
        "cluster_id": user_cluster,
        "avg_transaction": round(avg_amount, 2),
        "max_transaction": round(max_amount, 2),
        "most_common_type": most_common_type,
        "peak_hour": peak_hour,
        "total_transactions": len(txs),
        "insights": insights
    }


# ══════════════════════════════════════════════════════════
# 4. TRANSACTION PREDICTION — Linear Regression
# ══════════════════════════════════════════════════════════

def predict_next_transaction(user_id: str) -> dict:
    """
    Uses Linear Regression on transaction index → amount
    to predict the next likely transaction amount.

    Returns:
      {
        predicted_amount: float,
        trend: "increasing" | "decreasing" | "stable",
        confidence: "low" | "medium" | "high",
        based_on: int  (number of transactions used)
      }
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT amount FROM transactions WHERE user_id=%s AND tx_type IN ('DEBIT','TRANSFER_OUT','NEFT') ORDER BY timestamp ASC LIMIT 50",
        (user_id,)
    ).fetchall()
    conn.close()

    amounts = [r["amount"] for r in rows]

    if len(amounts) < 5:
        return {
            "predicted_amount": 0,
            "trend": "unknown",
            "confidence": "low",
            "based_on": len(amounts),
            "message": "Need at least 5 transactions to predict"
        }

    X = np.array(range(len(amounts))).reshape(-1, 1)
    y = np.array(amounts)

    model = LinearRegression()
    model.fit(X, y)

    next_index = np.array([[len(amounts)]])
    predicted = float(model.predict(next_index)[0])
    predicted = max(0, predicted)

    slope = model.coef_[0]
    r2    = model.score(X, y)

    if slope > 50:
        trend = "increasing"
    elif slope < -50:
        trend = "decreasing"
    else:
        trend = "stable"

    if r2 > 0.7:
        confidence = "high"
    elif r2 > 0.4:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "predicted_amount": round(predicted, 2),
        "trend": trend,
        "confidence": confidence,
        "r2_score": round(r2, 3),
        "slope": round(slope, 2),
        "based_on": len(amounts),
        "avg_recent": round(float(np.mean(amounts[-5:])), 2)
    }


# ══════════════════════════════════════════════════════════
# 5. AUTH ANOMALY — Unusual Login Detection
# ══════════════════════════════════════════════════════════

def detect_auth_anomaly(user_id: str) -> dict:
    """
    Checks if the current login is anomalous based on:
      - Time of day vs user's normal login hours
      - Login frequency spike
      - Recent failure rate

    Returns:
      {
        is_anomalous: bool,
        anomaly_score: float (0-100),
        signals: dict
      }
    """
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM auth_log WHERE user_id=%s AND event_type LIKE '%%LOGIN%%' ORDER BY timestamp DESC LIMIT 50",
        (user_id,)
    ).fetchall()
    conn.close()

    logs = [dict(r) for r in logs]
    current_hour = datetime.now().hour

    if len(logs) < 3:
        return {
            "is_anomalous": False,
            "anomaly_score": 0,
            "signals": {"message": "Insufficient login history"},
            "recommendation": "Monitor"
        }

    # Extract hours of past logins
    login_hours = []
    for log in logs:
        try:
            ts = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            login_hours.append(ts.hour)
        except Exception:
            pass

    if not login_hours:
        return {"is_anomalous": False, "anomaly_score": 0, "signals": {}, "recommendation": "Proceed"}

    avg_hour = np.mean(login_hours)
    std_hour = np.std(login_hours) if len(login_hours) > 1 else 3
    hour_diff = abs(current_hour - avg_hour)

    # Login frequency in last 10 minutes
    ten_ago = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    recent_logins = conn.execute(
        "SELECT COUNT(*) as c FROM auth_log WHERE user_id=%s AND timestamp > %s",
        (user_id, ten_ago)
    ).fetchone()["c"]

    # Failure rate in last hour
    one_hr_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    fail_rate_row = conn.execute(
        "SELECT COUNT(*) as c FROM auth_log WHERE user_id=%s AND event_type LIKE '%%FAIL%%' AND timestamp > %s",
        (user_id, one_hr_ago)
    ).fetchone()
    conn.close()
    fail_count = fail_rate_row["c"]

    # Score
    score = 0
    if std_hour > 0 and hour_diff > 2 * std_hour:
        score += 40
    if recent_logins > 3:
        score += 30
    if fail_count >= 2:
        score += 30

    score = min(score, 100)
    is_anomalous = score >= 40

    return {
        "is_anomalous": is_anomalous,
        "anomaly_score": score,
        "signals": {
            "current_hour": current_hour,
            "typical_login_hour": round(avg_hour, 1),
            "hour_deviation": round(hour_diff, 1),
            "recent_login_attempts_10min": recent_logins,
            "failed_attempts_1hr": fail_count
        },
        "recommendation": "Flag for review" if is_anomalous else "Normal login pattern"
    }


# ══════════════════════════════════════════════════════════
# 6. FULL ML REPORT — Combined summary for a user
# ══════════════════════════════════════════════════════════

def generate_ml_report(user_id: str) -> dict:
    """
    Generates a full ML intelligence report for a user.
    Called by /api/ml/report/<user_id> endpoint.
    """
    spending  = analyse_spending_pattern(user_id)
    prediction = predict_next_transaction(user_id)
    auth_check = detect_auth_anomaly(user_id)

    return {
        "user_id": user_id,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "spending_pattern": spending,
        "next_transaction_prediction": prediction,
        "auth_anomaly": auth_check,
        "models_used": [
            "KMeans (spending clusters)",
            "LinearRegression (transaction prediction)",
            "Rule-based (auth anomaly)"
        ]
    }
