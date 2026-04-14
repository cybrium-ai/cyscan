# Deliberate-bad sample file for cyscan integration tests.
# Every block below should raise at least one finding.

import sqlite3

AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"  # CBR-SECRETS-AWS-KEY

def lookup(conn, email):
    cursor = conn.cursor()
    # CBR-PY-SQLI-STRING-CONCAT
    cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")
    return cursor.fetchall()
