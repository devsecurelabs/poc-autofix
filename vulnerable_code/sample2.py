from flask import Flask, request
import os
import sqlite3

app = Flask(__name__)

# --- SQL Injection Vulnerability ---
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # ❌ Vulnerable query (no parameterization)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    else:
        return "Invalid credentials"


# --- Command Injection Vulnerability ---     
@app.route('/ping', methods=['GET'])
def ping():
    ip = request.args.get('ip')

    # ❌ Directly passing user input into shell    
    result = os.popen(f"ping -c 1 {ip}").read()

    return f"<pre>{result}</pre>"


if __name__ == '__main__':
    app.run(debug=True)