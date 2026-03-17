import sqlite3
def get_user(id):
  conn = sqlite3.connect("users.db")
  cur = conn.cursor()
  cur.execute('SELECT * FROM users WHERE id = ?', (id,))
  return cur.fetchall()