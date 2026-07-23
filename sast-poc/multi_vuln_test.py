"""
POC con 5 vulnerabilita' distinte per verificare che la pipeline SAST
(CodeQL + Bandit) le rilevi davvero e le porti nella tab Security.

Ogni funzione e' isolata e usa flask.request diretto (non Connexion),
cosi' evitiamo il gap di taint-tracking gia' scoperto in precedenza.
"""
from flask import Flask, request
import sqlite3
import os
import hashlib
import pickle

app = Flask(__name__)


# 1. SQL Injection (CWE-89) — Bandit B608, CodeQL py/sql-injection
@app.route("/vuln/sqli", methods=["POST"])
def vuln_sqli():
    data = request.get_json()
    username = data.get("username", "")
    conn = sqlite3.connect("test.db")
    c = conn.cursor()
    query = "SELECT * FROM users WHERE username = '%s'" % username
    c.execute(query)
    return str(c.fetchone())


# 2. Command Injection (CWE-78) — Bandit B605/B607, CodeQL py/command-line-injection
@app.route("/vuln/cmd", methods=["POST"])
def vuln_command_injection():
    data = request.get_json()
    hostname = data.get("hostname", "")
    output = os.system("ping -c 1 " + hostname)
    return str(output)


# 3. Code Injection via eval (CWE-95) — Bandit B307, CodeQL py/code-injection
@app.route("/vuln/eval", methods=["POST"])
def vuln_eval():
    data = request.get_json()
    expression = data.get("expression", "")
    result = eval(expression)
    return str(result)


# 4. Credenziali hardcoded (CWE-798) — Bandit B105/B106, CodeQL py/hardcoded-credentials
def vuln_hardcoded_credentials():
    db_password = "SuperSegreta123!"
    api_key = "sk-live-51H8x9K2eZvKYlo2C"
    return db_password, api_key


# 5. Hash debole per password (CWE-327) — Bandit B303/B324, CodeQL py/weak-sensitive-data-hashing
@app.route("/vuln/weakhash", methods=["POST"])
def vuln_weak_hash():
    data = request.get_json()
    password = data.get("password", "")
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


if __name__ == "__main__":
    app.run(port=9998, debug=True)