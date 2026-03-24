// Author: Jeremy Quadri
// src/constants.ts — Deterministic configuration constants for the DevSecure L1 Detection Plane (v2.0).
// All arrays are exported as const (readonly tuples) for compile-time type safety.

// ---------------------------------------------------------------------------
// Requirement 6 — Severity Gating: CWE Bypass List
// ---------------------------------------------------------------------------

/**
 * Per Board-approved Requirement 6: findings matching these CWE categories bypass severity gating
 * and always escalate to L2 regardless of scanner confidence.
 */
export const CRITICAL_CWE_BYPASS = [
  "CWE-22",  // Path Traversal
  "CWE-77",  // Command Injection
  "CWE-78",  // OS Command Injection
  "CWE-79",  // Cross-Site Scripting (XSS)
  "CWE-89",  // SQL Injection
  "CWE-94",  // Code Injection / RCE
  "CWE-287", // Improper Authentication
  "CWE-306", // Missing Authentication for Critical Function
  "CWE-502", // Deserialisation of Untrusted Data
  "CWE-862", // Missing Authorization
  "CWE-918", // Server-Side Request Forgery (SSRF)
] as const;

// ---------------------------------------------------------------------------
// Requirement 10 — No-Detection Escalation: High-Risk File Patterns
// ---------------------------------------------------------------------------

/**
 * Per Board-approved Requirement 10: files matching these patterns trigger No-Detection Escalation
 * when both scanners return zero findings.
 */
export const HIGH_RISK_FILE_PATTERNS = [
  // Authentication and authorisation
  "auth",
  "login",
  "logout",
  "signin",
  "signup",
  "permission",
  "rbac",
  "acl",
  "oauth",
  // Database and query construction
  "db",
  "database",
  "query",
  "repository",
  "dao",
  "orm",
  "migration",
  "sql",
  // Session management
  "session",
  "cookie",
  "token",
  "jwt",
  // Cryptographic operations
  "crypto",
  "cipher",
  "encrypt",
  "decrypt",
  "hash",
  "hmac",
  "certificate",
  "tls",
  "ssl",
  // Input parsing and validation
  "parser",
  "sanitize",
  "validate",
  "input",
  "deserialize",
  "unmarshal",
  // API endpoint definitions
  "route",
  "controller",
  "endpoint",
  "handler",
  "middleware",
  "api",
] as const;

// ---------------------------------------------------------------------------
// Requirement 4 — Path-Based Filtering: Excluded Paths
// ---------------------------------------------------------------------------

/**
 * Per Board-approved Requirement 4: findings from these paths are excluded before L2 classification.
 * Content-type validation (Magika) must verify file type before exclusion is applied.
 */
export const EXCLUDED_PATHS = [
  // Test directories
  "/test/",
  "/tests/",
  "/__tests__/",
  "/spec/",
  "/fixtures/",
  "/__mocks__/",
  // Vendor and dependencies
  "/node_modules/",
  "/vendor/",
  "/third_party/",
  // Generated and compiled output
  "/dist/",
  "/build/",
  "/out/",
  "/.next/",
  "/coverage/",
  // Documentation and examples
  "/docs/",
  "/examples/",
  "/documentation/",
  // Database migrations (auto-generated)
  "/migrations/",
] as const;

// ---------------------------------------------------------------------------
// Requirement 4 — Path-Based Filtering: Excluded File Patterns
// ---------------------------------------------------------------------------

/**
 * Per Board-approved Requirement 4: file-level glob exclusions applied before L2 classification.
 * Separate from directory-level EXCLUDED_PATHS.
 */
export const EXCLUDED_FILE_PATTERNS = [
  "*.test.js",
  "*.test.ts",
  "*.spec.js",
  "*.spec.ts",
  "*_test.go",
  "*_test.py",
  "*.test.jsx",
  "*.test.tsx",
  "*.stories.js",
  "*.stories.tsx",
  "*.generated.*",
  "*.pb.go",
  "*.pb.ts",
  "*.min.js",
  "*.min.css",
  "*.d.ts",
] as const;

// ---------------------------------------------------------------------------
// Requirement 6 — Severity Gating Thresholds
// ---------------------------------------------------------------------------

/**
 * Per Board-approved Requirement 6: findings below min_confidence AND matching drop_severities
 * are filtered out, UNLESS the CWE matches CRITICAL_CWE_BYPASS.
 */
export const SEVERITY_GATE_THRESHOLDS = {
  min_confidence:  0.3,
  drop_severities: ["INFO"] as const,
} as const;

// ---------------------------------------------------------------------------
// Requirement 3 — Deduplication: Fuzzy Line Proximity Threshold
// ---------------------------------------------------------------------------

/**
 * Per Board-approved Requirement 3: two findings in the same file, within this many lines,
 * sharing the same CWE category, are treated as likely duplicates and merged.
 */
export const DEDUP_PROXIMITY_LINES = 5;
