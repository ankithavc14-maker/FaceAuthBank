"""PostgreSQL database utilities for FaceAuthBank.

Uses psycopg 3 and DATABASE_URL from the environment.
"""
import os
import re
from pathlib import Path
import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_NAME = "faceauthbank"

SCHEMA = """
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
"""

def database_url():
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Create a PostgreSQL database and set "
            "DATABASE_URL, e.g. postgresql://postgres:password@localhost:5432/faceauthbank"
        )
    # Render and some managed services may expose postgres://; psycopg expects postgresql://.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"): ]
    return url

class PGConnection:
    """Small compatibility wrapper so the existing project can keep conn.execute(...)."""
    def __init__(self, conn):
        self._conn = conn

    @staticmethod
    def _convert_sql(sql):
        # Existing project uses SQLite-style ? placeholders. Convert them to psycopg %s.
        return sql.replace("?", "%s")

    def execute(self, sql, params=None):
        # Existing project uses SQLite-style ? placeholders. Convert them first.
        sql = self._convert_sql(sql)
        if params is None or params == () or params == []:
            # No bound parameters: literal % characters are safe as-is.
            return self._conn.execute(sql)

        # psycopg treats % as a placeholder marker whenever parameters are
        # supplied. The legacy SQL contains LIKE '%FAIL%', '%LOGIN%', etc.
        # Escape literal percent signs while preserving supported placeholders
        # (%s, %b, %t and %(name)s). This keeps the existing SQL compatible
        # without requiring every query in the project to be rewritten.
        sql = re.sub(r'%(?![sbt(])', '%%', sql)
        return self._conn.execute(sql, params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()

def get_db():
    conn = psycopg.connect(database_url(), row_factory=dict_row)
    return PGConnection(conn)

def init_db():
    conn = get_db()
    try:
        # SCHEMA contains independent statements; execute one at a time for psycopg.
        for statement in SCHEMA.split(";"):
            statement = statement.strip()
            if statement:
                conn.execute(statement)
        # Safe migrations for databases created by earlier versions.
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS face_enrolled BOOLEAN DEFAULT FALSE")
        conn.commit()
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    print("PostgreSQL schema initialized successfully.")
