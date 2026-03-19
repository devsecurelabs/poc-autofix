import sqlite3

def get_user_by_id(user_id):
    # Connect to a dummy database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: Raw string formatting allows SQL Injection
    # An attacker could provide "1; DROP TABLE users;" 
    query = "SELECT username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

if __name__ == "__main__":
    # Test call
    print(get_user_by_id("1"))