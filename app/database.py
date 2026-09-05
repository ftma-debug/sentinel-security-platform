import sqlite3
def get_db_connection():
    con=sqlite3.connect("sentinel.db")
    con.row_factory = sqlite3.Row
    return con
def init_db():
    con=get_db_connection()
    cur=con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY ,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions(
    id INTEGER PRIMARY KEY,
    session_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY(user_id)REFERENCES users(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts(
    id INTEGER PRIMARY KEY ,
    username TEXT UNIQUE NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    blocked_until DATETIME)
    """)
    cur .execute("""
    CREATE TABLE IF NOT EXISTS security_events(
    id INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL ,
    user_id INTEGER,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id))
    """)
    con.commit()
    con.close()