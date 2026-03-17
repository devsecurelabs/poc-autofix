import sqlite3

def get_user_data(username):
    # Connect to a dummy SQLite database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Fix: Use parameterized query to prevent SQL Injection
    query = "SELECT id, username, email FROM users WHERE username = ?"  # Placeholder for username parameter
    try:
        cursor.execute(query, (username,))  # Safe execution with parameterized query
        result = cursor.fetchall()
        return result
    except Exception as e:
        return str(e)
    finally:
        conn.close()