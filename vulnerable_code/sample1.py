import sqlite3

def get_user_data(username):
    # Connect to a dummy SQLite database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Fixed vulnerability: Use parameterized queries
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    try:
        result = cursor.fetchall()
        return result
    except Exception as e:
        return str(e)
    finally:
        conn.close()