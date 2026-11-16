# Deliberate-bad sample file for cyscan integration tests (v1.2.2 recall set).
import subprocess
import xml.etree.ElementTree as ET

import jwt
import requests


def run(command):
    # CBR-PY-SUBPROCESS-SHELL-TRUE — keyword on its own line
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
    )


def fetch(url):
    # CBR-PY-REQUESTS-VERIFY-FALSE — keyword on its own line
    return requests.get(
        url,
        timeout=5,
        verify=False,
    )


def claims(id_token):
    # CBR-PY-JWT-VERIFY-DISABLED
    return jwt.decode(id_token, options={"verify_signature": False})


def lookup(cursor, table, email):
    # CBR-PY-SQLI-FORMATTED-QUERY
    cursor.execute(f"SELECT * FROM {table} WHERE email = '{email}'")
    # parameterised — must NOT fire
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))


def load(path):
    # CBR-PY-XML-UNSAFE-PARSE
    return ET.parse(path).getroot()
