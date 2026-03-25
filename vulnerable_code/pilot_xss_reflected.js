// Author: Jeremy Quadri
// Target CWE: CWE-79 (Cross-Site Scripting — Reflected)
// Expected detection signal: CONVERGED or PATTERN_ONLY
// Reason: CWE-79 is in the CRITICAL_CWE_BYPASS list. Even if a scanner reports
//         low confidence, the severity gate must NOT drop this finding.
//         This exercises the CWE bypass mechanism in the L1.5 Pre-Filter.

const express = require('express');
const app = express();

// CWE-79: Reflected XSS — user input directly in response
// Expected: Flagged by at least one scanner.
// Must survive severity gate regardless of confidence (CWE bypass).
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Search results for: ${query}</h1>`);
});
