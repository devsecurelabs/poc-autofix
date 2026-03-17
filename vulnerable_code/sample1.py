def get_user_data(username):
    # Connect to a dummy SQLite database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: String concatenation allows SQL Injection!
    # An attacker could pass a username like: admin' OR '1'='1
    query = "SELECT id, username, email FROM users WHERE username = ?";
    params = (username,);
    try:
        cursor.execute(query, params)
        result = cursor.fetchall()
        return result
    except Exception as e:
        return str(e)
    finally:
        conn.close()