// Author: Jeremy Quadri
// research_target.ts — Constrained Autoresearch configuration for DevSecure v4.0.
//
// TUNABLE values may be adjusted by autoresearch experiments.
// IMMUTABLE values are enforced as const — TypeScript will reject any attempt to widen or mutate them.

// ---------------------------------------------------------------------------
// TUNABLE — experiment-facing knobs
// ---------------------------------------------------------------------------

/** Lane routing penalty subtracted from final_priority_score. Lane 1 = no penalty. */
export const LANE_WEIGHTS = {
  1:  0,
  2:  5,
  3: 10,
  4: 20,
} as const;

/** Absolute changed-line ceiling for files shorter than SMALL_FILE_THRESHOLD (50 lines). */
export const SMALL_FILE_MAX_LINES = 20;

/** Verification Bonus parameters awarded when the Diversity Judge approves the patch. */
export const VERIFICATION_BONUS = {
  /** Credit when LLM classification confidence >= 0.85. */
  HIGH_CONFIDENCE_CREDIT: 10,
  /** Credit when LLM classification confidence < 0.85. */
  LOW_CONFIDENCE_CREDIT: 5,
  /** Additional corroboration credit implied by full checklist pass. */
  CORROBORATION_CREDIT: 5,
} as const;

/** Patch risk penalty brackets keyed by changePercent upper bound (inclusive).
 *  Evaluated in order; the first matching bracket wins. */
export const PATCH_RISK_BRACKETS: ReadonlyArray<{ maxPercent: number; penalty: number }> = [
  { maxPercent: 10, penalty:  0 },
  { maxPercent: 15, penalty:  5 },
  { maxPercent: Infinity, penalty: 10 },
] as const;

// ---------------------------------------------------------------------------
// IMMUTABLE — TypeScript enforces these cannot be widened or mutated
// ---------------------------------------------------------------------------

/** Minimum final_priority_score required to open a PR. Below this → L4 escalation. */
export const AUTO_MERGE_THRESHOLD = 70 as const;

/**
 * CWE severity base scores (0–100).
 * Fail-closed default: 80 (HIGH) for any unrecognised CWE.
 * `as const` ensures values are readonly literal types — no accidental mutation.
 */
export const CWE_SEVERITY = {
  // ── Injection / RCE (Critical) ───────────────────────────────────────────
  "CWE-78":  90,  // OS Command Injection
  "CWE-89":  90,  // SQL Injection
  "CWE-77":  90,  // Command Injection (generic)
  "CWE-94":  85,  // Code Injection
  "CWE-502": 90,  // Deserialization of Untrusted Data
  "CWE-20":  80,  // Improper Input Validation

  // ── Authentication / Access Control (High) ──────────────────────────────
  "CWE-287": 85,  // Improper Authentication
  "CWE-284": 80,  // Improper Access Control
  "CWE-862": 85,  // Missing Authorization
  "CWE-269": 85,  // Improper Privilege Management
  "CWE-522": 80,  // Insufficiently Protected Credentials

  // ── Sensitive Data Exposure (Medium-High) ───────────────────────────────
  "CWE-200": 75,  // Exposure of Sensitive Information
  "CWE-319": 75,  // Cleartext Transmission of Sensitive Data
  "CWE-327": 75,  // Use of Broken/Risky Cryptographic Algorithm
  "CWE-326": 75,  // Inadequate Encryption Strength

  // ── Client-Side / Web (Medium) ──────────────────────────────────────────
  "CWE-79":  70,  // Cross-Site Scripting (XSS)
  "CWE-352": 70,  // Cross-Site Request Forgery (CSRF)
  "CWE-601": 65,  // Open Redirect

  // ── File / Path (High) ──────────────────────────────────────────────────
  "CWE-22":  80,  // Path Traversal
  "CWE-434": 80,  // Unrestricted File Upload
  "CWE-73":  75,  // External Control of File Name or Path

  // ── Resource / Memory (Medium) ──────────────────────────────────────────
  "CWE-400": 65,  // Uncontrolled Resource Consumption
  "CWE-476": 60,  // NULL Pointer Dereference
  "CWE-787": 85,  // Out-of-bounds Write

  // ── Configuration / Info Disclosure (Low-Medium) ────────────────────────
  "CWE-16":  60,  // Configuration
  "CWE-209": 60,  // Error Message Information Exposure
  "CWE-215": 60,  // Information Exposure Through Debug Info
} as const;

// ---------------------------------------------------------------------------
// Composed export — single import surface for consumers
// ---------------------------------------------------------------------------

export const RESEARCH_CONFIG = {
  // TUNABLE
  LANE_WEIGHTS,
  SMALL_FILE_MAX_LINES,
  VERIFICATION_BONUS,
  PATCH_RISK_BRACKETS,
  // IMMUTABLE
  AUTO_MERGE_THRESHOLD,
  CWE_SEVERITY,
} as const;
