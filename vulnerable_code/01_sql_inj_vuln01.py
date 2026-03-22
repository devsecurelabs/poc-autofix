import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user1")
def get_user():
    username = request.args.get("username")

    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()

    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"

    result = cursor.execute(query).fetchall()

    return str(result)

if __name__ == "__main__":
    app.run()
