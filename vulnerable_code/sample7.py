import sqlite3

def get_user_data(user_input):
    # Connect to a dummy database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # VULNERABLE: Directly concatenating user input into the SQL query 
    query = f"SELECT id, username, email FROM users WHERE username = '{user_input}'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        print(f"Executing Query: {query}")
        return result
    except Exception as e:
        return str(e)
    finally:
        conn.close()

# Example of normal usage:
# get_user_data("alice") 
# Becomes: SELECT id, username, email FROM users WHERE username = 'alice'