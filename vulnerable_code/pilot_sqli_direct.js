// [SECURITY REMEDIATION]
// TYPE: CWE-89
// TIMESTAMP: 2026-03-25
// BY: DevSecure Autonomous Surgeon (L3-32B)
// Author: Jeremy Quadri
// Target CWE: CWE-89 (SQL Injection)
// Expected detection signal: CONVERGED
// Reason: Both OpenGrep (string concatenation pattern in SQL context) and
//         Bearer (taint flow from req.query to db.get) should independently flag this.

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');
const app = express();

// CWE-89: Fixed SQL injection via parameterized queries
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = ?";
  db.get(query, [userId], (err, row) => {
    if (err) return res.status(500).send(err.message);
    res.json(row);
  });
});