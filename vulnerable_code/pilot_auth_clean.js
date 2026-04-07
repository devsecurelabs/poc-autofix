// Author: Jeremy Quadri
// Target CWE: None — intentionally clean file
// Expected detection signal: NO_DETECTION_ESCALATION
// Reason: This file contains no vulnerabilities. Both scanners should return zero
//         findings. However, because the filename contains 'auth', it matches
//         HIGH_RISK_FILE_PATTERNS (Requirement 10), which must trigger a
//         NO_DETECTION_ESCALATION payload sending this file to L2 for heuristic review.

// This file is intentionally clean — no vulnerabilities.
// Expected: Both scanners find nothing.
// Because the filename contains 'auth', Requirement 10 should trigger
// NO_DETECTION_ESCALATION, sending this to L2 for heuristic review.

function validateAuthToken(token) {
  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'Token is required' };
  }
  if (token.length < 32) {
    return { valid: false, reason: 'Token too short' };
  }
  return { valid: true };
}

module.exports = { validateAuthToken };
