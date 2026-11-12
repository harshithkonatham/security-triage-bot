"""User and table queries."""

import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    query = f"SELECT id, email FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchone()


def count_rows(conn: sqlite3.Connection, table: str) -> int:
    if table not in {"users", "orders"}:
        raise ValueError(f"unknown table: {table}")
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
