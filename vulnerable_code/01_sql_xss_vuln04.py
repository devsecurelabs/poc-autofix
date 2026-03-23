import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user4")
def user():
    username = request.args.get("username")

    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()

    # SQL Injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    result = cursor.execute(query).fetchall()

    # XSS
    return "<h1>User: " + username + "</h1>" + str(result)

if __name__ == "__main__":
    app.run()
