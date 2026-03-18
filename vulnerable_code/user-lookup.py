from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/get-user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # VULNERABILITY: String formatting allows SQL Injection
    query = f"SELECT username, email FROM users WHERE id = '{user_id}'"
    
    cursor.execute(query)
    return str(cursor.fetchone())