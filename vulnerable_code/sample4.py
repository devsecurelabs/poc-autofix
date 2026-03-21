import sqlite3
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# VULNERABILITY 1: SQL Injection
@app.route("/get-user")
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # DANGER: String concatenation in SQL
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return str(cursor.fetchall())

# VULNERABILITY 2: Command Injection
@app.route("/ping")
def ping_host():
    target = request.args.get('target')
    # DANGER: Direct execution of user input in a shell
    cmd = f"ping -c 1 {target}"
    output = subprocess.check_output(cmd, shell=True)
    return output

# VULNERABILITY 3: Path Traversal
@app.route("/read-file")
def read_file():
    filename = request.args.get('file')
    # DANGER: No validation on filename; can be "../../etc/passwd"
    with open(os.path.join("content", filename), "r") as f:
        return f.read()

if __name__ == "__main__":
    app.run(port=5000)