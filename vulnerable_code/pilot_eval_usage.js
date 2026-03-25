// [SECURITY REMEDIATION]
// TYPE: CWE-94
// TIMESTAMP: 2026-03-25
// BY: DevSecure Autonomous Surgeon (L3-32B)
// Author: Jeremy Quadri
// Target CWE: CWE-94 (Code Injection via eval)
// Expected detection signal: PATTERN_ONLY
// Reason: OpenGrep will pattern-match the eval() call directly.
//         Bearer may not flag it because the input originates from a config file
//         (fs.readFileSync), which Bearer may not model as an external taint source.
//         This exercises the PATTERN_ONLY signal path.

// CWE-94: Use of eval with dynamic input
// Fixed: Replaced eval() with safe alternative - JSON parsing for configuration
const fs = require('fs');

function loadPlugin(configPath) {
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  // Safe: Using JSON.parse for configuration data instead of eval
  const result = JSON.parse(config.initScript);
  return result;
}

module.exports = { loadPlugin };