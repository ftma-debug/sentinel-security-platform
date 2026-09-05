from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Response,Request
from fastapi import Depends
from pydantic import BaseModel
import secrets
import sqlite3
import requests 
from passlib.context import CryptContext
from datetime import datetime,timedelta
BASE_URL = "http://127.0.0.1:8000"
DB = "sentinel.db"

ADMIN_USERNAME = "fatima"
ADMIN_PASSWORD = "tahyaljazayer"

USER_USERNAME = "mary"
USER_PASSWORD = "123"


def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def get_user_id(username):
    con = get_db()
    user = con.execute(
        "SELECT id FROM users WHERE username=?",
        (username,)
    ).fetchone()
    con.close()

    if not user:
        raise Exception(f"User '{username}' does not exist")

    return user["id"]


def get_events_after(event_id):
    con = get_db()

    events = con.execute("""
        SELECT id, event_type, user_id, ip_address, timestamp
        FROM security_events
        WHERE id > ?
        ORDER BY id
    """, (event_id,)).fetchall()

    con.close()
    return events


def latest_event_id():
    con = get_db()

    row = con.execute(
        "SELECT COALESCE(MAX(id), 0) AS id FROM security_events"
    ).fetchone()

    con.close()
    return row["id"]


def print_test(number, name, expected):
    print(f"\n{'=' * 60}")
    print(f"TEST {number}: {name}")
    print(f"Expected: {expected}")


def main():

    print("\n🔐 SENTINEL SECURITY EVENTS TEST")
    print("=" * 60)

    admin_id = get_user_id(ADMIN_USERNAME)
    user_id = get_user_id(USER_USERNAME)

    print(f"Admin {ADMIN_USERNAME} → ID {admin_id}")
    print(f"User  {USER_USERNAME} → ID {user_id}")

    start_event_id = latest_event_id()

    # ---------------------------------------------------------
    # TEST 1 — Successful login
    # ---------------------------------------------------------

    print_test(
        1,
        "Successful login",
        "LOGIN_SUCCESS + SESSION_CREATED"
    )

    admin_session = requests.Session()

    r = admin_session.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # TEST 2 — Wrong password
    # ---------------------------------------------------------

    print_test(
        2,
        "Wrong password",
        "LOGIN_FAILURE"
    )

    r = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": ADMIN_USERNAME,
            "password": "WRONG_PASSWORD"
        }
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # TEST 3 — Nonexistent username
    # ---------------------------------------------------------

    print_test(
        3,
        "Nonexistent username",
        "LOGIN_FAILURE with user_id=NULL"
    )

    r = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": "user_that_does_not_exist_999",
            "password": "anything"
        }
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # TEST 4 — LOGIN_BLOCKED
    # ---------------------------------------------------------

    print_test(
        4,
        "Blocked login",
        "LOGIN_BLOCKED"
    )

    con = get_db()

    blocked_until = datetime.utcnow() + timedelta(minutes=5)

    con.execute("""
        INSERT INTO login_attempts
        (username, failed_attempts, blocked_until)
        VALUES (?, ?, ?)
        ON CONFLICT(username)
        DO UPDATE SET
            failed_attempts=excluded.failed_attempts,
            blocked_until=excluded.blocked_until
    """, (
        USER_USERNAME,
        5,
        blocked_until.isoformat()
    ))

    con.commit()
    con.close()

    r = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": USER_USERNAME,
            "password": USER_PASSWORD
        }
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # Clean the artificial block
    con = get_db()
    con.execute(
        "DELETE FROM login_attempts WHERE username=?",
        (USER_USERNAME,)
    )
    con.commit()
    con.close()

    # ---------------------------------------------------------
    # TEST 5 — Unauthenticated access
    # ---------------------------------------------------------

    print_test(
        5,
        "Unauthenticated access",
        "UNAUTHORIZED_ACCESS"
    )

    r = requests.get(
        f"{BASE_URL}/users/{admin_id}"
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # TEST 6 — Invalid session
    # ---------------------------------------------------------

    print_test(
        6,
        "Invalid session",
        "INVALID_SESSION"
    )

    fake_session = requests.Session()

    fake_session.cookies.set(
        "session_id",
        "THIS_IS_NOT_A_REAL_SESSION"
    )

    r = fake_session.get(
        f"{BASE_URL}/users/{admin_id}"
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # TEST 7 — Expired session
    # ---------------------------------------------------------

    print_test(
        7,
        "Expired session",
        "SESSION_EXPIRED"
    )

    expired_session_id = secrets.token_urlsafe(32)

    created_at = datetime.utcnow() - timedelta(hours=2)
    expires_at = datetime.utcnow() - timedelta(hours=1)

    con = get_db()

    con.execute("""
        INSERT INTO sessions
        (session_id, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (
        expired_session_id,
        admin_id,
        created_at,
        expires_at
    ))

    con.commit()
    con.close()

    expired_session = requests.Session()

    expired_session.cookies.set(
        "session_id",
        expired_session_id
    )

    r = expired_session.get(
        f"{BASE_URL}/users/{admin_id}"
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # TEST 8 — Forbidden access
    # ---------------------------------------------------------

    print_test(
        8,
        "Normal user accessing admin/user resource",
        "FORBIDDEN_ACCESS"
    )

    mary_session = requests.Session()

    r = mary_session.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": USER_USERNAME,
            "password": USER_PASSWORD
        }
    )

    print("Mary login:", r.status_code)

    r = mary_session.get(
        f"{BASE_URL}/users/{admin_id}"
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # TEST 9 — Session rotation
    # ---------------------------------------------------------

    print_test(
        9,
        "Second login while valid session exists",
        "SESSION_ROTATED"
    )

    rotation_session = requests.Session()

    # First login
    r = rotation_session.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }
    )

    first_cookie = rotation_session.cookies.get("session_id")

    print("First login:", r.status_code)
    print("First session created:", bool(first_cookie))

    # Second login
    r = rotation_session.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }
    )

    second_cookie = rotation_session.cookies.get("session_id")

    print("Second login:", r.status_code)
    print("Second session created:", bool(second_cookie))
    print("Session changed:", first_cookie != second_cookie)

    # ---------------------------------------------------------
    # TEST 10 — Logout
    # ---------------------------------------------------------

    print_test(
        10,
        "Logout",
        "LOGOUT"
    )

    r = rotation_session.post(
        f"{BASE_URL}/auth/logout"
    )

    print("HTTP:", r.status_code)
    print("Response:", r.text)

    # ---------------------------------------------------------
    # RESULTS
    # ---------------------------------------------------------

    print("\n\n")
    print("=" * 70)
    print("📋 SECURITY EVENTS GENERATED")
    print("=" * 70)

    events = get_events_after(start_event_id)

    for event in events:
        print(
            f"[{event['id']}] "
            f"{event['event_type']:25} "
            f"user_id={str(event['user_id']):5} "
            f"ip={event['ip_address']}"
        )

    print("\n")
    print("=" * 70)
    print("EXPECTED EVENT TYPES")
    print("=" * 70)

    expected_events = [
        "LOGIN_SUCCESS",
        "SESSION_CREATED",
        "LOGIN_FAILURE",
        "LOGIN_FAILURE",
        "LOGIN_BLOCKED",
        "UNAUTHORIZED_ACCESS",
        "INVALID_SESSION",
        "SESSION_EXPIRED",
        "LOGIN_SUCCESS",
        "SESSION_CREATED",
        "FORBIDDEN_ACCESS",
        "LOGIN_SUCCESS",
        "SESSION_ROTATED",
        "LOGOUT"
    ]

    generated_types = [event["event_type"] for event in events]

    for event_type in expected_events:
        if event_type in generated_types:
            print(f"✅ {event_type}")
        else:
            print(f"❌ {event_type} MISSING")

    print("\n")
    print("🎯 Test run finished.")
    print("You can also verify everything with:")
    print("SELECT * FROM security_events ORDER BY id;")


if __name__ == "__main__":
    main()
