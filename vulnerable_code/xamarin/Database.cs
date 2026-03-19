using SQLite;
using System.Collections.Generic;

// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// VULNERABLE: String concatenation in SQLiteCommand constructor
// An attacker can supply id=1; DROP TABLE Users;-- to destroy data

public class Database
{
    private SQLiteConnection connection;

    public List<User> GetUser(string id)
    {
        var command = new SQLiteCommand("SELECT * FROM Users WHERE Id = " + id, connection);
        return command.ExecuteQuery<User>();
    }
}
