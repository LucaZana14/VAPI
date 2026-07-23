"""
POC minimale per il confronto SAST/DAST.

Replica esattamente lo stesso pattern vulnerabile di vAPI.py (get_token):
concatenazione diretta con %s dentro la query SQL, dato preso dal body JSON
della richiesta. L'unica differenza è la sorgente del dato non fidato:
qui e' flask.request diretto, in vAPI.py e' connexion.request.

Se CodeQL segnala SQLi qui ma non in vAPI.py, conferma che il gap e'
nel modeling del taint attraverso il layer Connexion, non un limite
generico di CodeQL sulle SQL injection in Python/Flask.
"""
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect("test.db")
    c = conn.cursor()

    # stessa identica concatenazione non parametrizzata di vAPI.py::get_token
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    c.execute(query)
    user = c.fetchone()

    return str(user)


if __name__ == "__main__":
    app.run(port=9999, debug=True)