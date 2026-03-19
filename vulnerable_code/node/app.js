const express = require('express');
const mysql = require('mysql');
const app = express();
const connection = mysql.createConnection({ host: 'localhost', user: 'root', database: 'test' });

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // VULNERABLE: Direct string interpolation in SQL query
  // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
  // An attacker can supply id=1' OR '1'='1 to dump the entire users table
  const sql = `SELECT * FROM users WHERE id = '${userId}'`;

  connection.query(sql, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.listen(3000);
