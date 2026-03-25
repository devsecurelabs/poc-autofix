// [SECURITY REMEDIATION]
// TYPE: CWE-89
// TIMESTAMP: 2026-03-25
// BY: DevSecure Autonomous Surgeon (L3-32B)
// Author: Jeremy Quadri
// Target CWE: CWE-89 (SQL Injection)
// Expected detection signal: DATAFLOW_ONLY
// Reason: OpenGrep should MISS this because the taint passes through a helper
//         function (no direct concatenation visible at the sink site).
//         Bearer's dataflow / taint analysis should trace the flow and catch it.

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');
const app = express();

// Helper that passes tainted data without sanitising
function buildQuery(table, filterField, filterValue) {
  return `SELECT * FROM ${table} WHERE ${filterField} = ?`;
}

// CWE-89: Indirect SQL injection via helper function
// Expected: Bearer catches taint flow, OpenGrep misses indirection → DATAFLOW_ONLY
app.get('/products', (req, res) => {
  const category = req.query.category;
  const sql = buildQuery('products', 'category', category);
  db.all(sql, [category], (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});