# [SECURITY REMEDIATION]
# TYPE: CWE-89
# TIMESTAMP: 2026-03-23
# BY: DevSecure Autonomous Surgeon (L3-32B)
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Fixed: Using parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchone())