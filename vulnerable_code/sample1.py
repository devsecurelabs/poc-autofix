import sqlite3

def get_user_data(username):
    # Connect to a dummy SQLite database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: String concatenation allows SQL Injection!
    # An attacker could pass a username like: admin' OR '1'='1
    query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        return str(e)
    finally:
        conn.close()

# Example of how an attacker might exploit this:
# print(get_user_data("admin' OR '1'='1"))