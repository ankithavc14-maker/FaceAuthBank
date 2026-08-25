-- FaceAuthBank PostgreSQL schema
-- The application initializes this automatically via db.py.
-- This file is provided for manual inspection / DBA workflows.

CREATE TABLE IF NOT EXISTS users (
    user_id        TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    fname          TEXT,
    lname          TEXT,
    email          TEXT UNIQUE,
    phone          TEXT,
    dob            TEXT,
    acct_no        TEXT UNIQUE,
    acct_type      TEXT DEFAULT 'savings',
    balance        DOUBLE PRECISION DEFAULT 0.0,
    id_type        TEXT,
    id_number      TEXT,
    nominee        TEXT,
    relation       TEXT,
    address        TEXT,
    created_at     TEXT,
    active         INTEGER DEFAULT 1,
    face_enrolled  BOOLEAN DEFAULT FALSE,
    total_credited DOUBLE PRECISION DEFAULT 0.0,
    total_debited  DOUBLE PRECISION DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id         TEXT PRIMARY KEY,
    user_id       TEXT REFERENCES users(user_id),
    tx_type       TEXT,
    amount        DOUBLE PRECISION,
    description   TEXT,
    balance_after DOUBLE PRECISION,
    ref_no        TEXT,
    cls           TEXT,
    icon           TEXT,
    timestamp     TEXT
);

CREATE TABLE IF NOT EXISTS auth_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    TEXT,
    event_type TEXT,
    message    TEXT,
    timestamp  TEXT
);

CREATE TABLE IF NOT EXISTS cards (
    card_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(user_id),
    type    TEXT,
    num     TEXT,
    expiry  TEXT,
    cvv     TEXT,
    virtual INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS fixed_deposits (
    fd_id      TEXT PRIMARY KEY,
    user_id    TEXT REFERENCES users(user_id),
    amount     DOUBLE PRECISION,
    tenure     INTEGER,
    maturity   TEXT,
    ref_no     TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS loans (
    loan_id    TEXT PRIMARY KEY,
    user_id    TEXT REFERENCES users(user_id),
    amount     DOUBLE PRECISION,
    tenure     INTEGER,
    emi        DOUBLE PRECISION,
    ref_no     TEXT,
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_transactions_user_time ON transactions(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auth_log_user_time ON auth_log(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(tx_type);
