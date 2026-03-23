import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # High-severity SQLi   
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return str(cursor.fetchone())