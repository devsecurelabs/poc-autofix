// Author: Jeremy Quadri
// Target CWE: CWE-94 (Code Injection via eval)
// Expected detection signal: PATTERN_ONLY
// Reason: OpenGrep will pattern-match the eval() call directly.
//         Bearer may not flag it because the input originates from a config file
//         (fs.readFileSync), which Bearer may not model as an external taint source.
//         This exercises the PATTERN_ONLY signal path.

// CWE-94: Use of eval with dynamic input
// Expected: OpenGrep catches eval() pattern, Bearer may miss (no external taint source) → PATTERN_ONLY
const fs = require('fs');

function loadPlugin(configPath) {
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  // Dangerous: executing arbitrary code from config
  const result = eval(config.initScript);
  return result;
}

module.exports = { loadPlugin };
