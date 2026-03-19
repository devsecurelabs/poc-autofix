import sqlite3

def get_user_by_id(user_id):
    # Connect to a dummy database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # FIXED: Using parameterized query to prevent SQL Injection
    query = "SELECT username, email FROM users WHERE id = ?"
    
    try:
        cursor.execute(query, (user_id,))
        return cursor.fetchone()
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

if __name__ == "__main__":
    # Test call
    print(get_user_by_id("1"))