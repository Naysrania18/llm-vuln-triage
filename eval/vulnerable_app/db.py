"""Sample code for evaluating the triage tool. DELIBERATELY VULNERABLE. Never deploy."""

import hashlib
import sqlite3


def get_user(conn: sqlite3.Connection, name: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + str(int(user_id)))
    return cur.fetchone()


def cache_key(name: str) -> str:
    return hashlib.md5(name.encode()).hexdigest()
