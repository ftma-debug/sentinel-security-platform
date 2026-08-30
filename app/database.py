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
    con.commit()
    con.close()