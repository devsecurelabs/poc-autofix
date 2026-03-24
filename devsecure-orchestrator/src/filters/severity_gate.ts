// Author: Jeremy Quadri
// src/filters/severity_gate.ts — Severity and confidence gating with CWE bypass (Requirement 6).

import { SEVERITY_GATE_THRESHOLDS, CRITICAL_CWE_BYPASS } from "../constants";
import type { RawScannerFinding, PreFilterStats } from "../types";

// ---------------------------------------------------------------------------
// 2a. Single-finding drop check
// ---------------------------------------------------------------------------

/**
 * Returns true if the finding should be dropped by the severity gate.
 *
 * Drop conditions (ALL must be true):
 *   1. confidence < min_confidence threshold
 *   2. severity is in drop_severities
 *   3. cwe_id is NOT in CRITICAL_CWE_BYPASS
 *
 * The CWE bypass takes absolute precedence — critical CWEs are NEVER dropped.
 */
export function shouldDropBySeverity(finding: RawScannerFinding): boolean {
  // CWE bypass: never drop critical findings regardless of confidence/severity
  if ((CRITICAL_CWE_BYPASS as readonly string[]).includes(finding.cwe_id)) {
    return false;
  }

  const belowConfidenceThreshold =
    finding.confidence < SEVERITY_GATE_THRESHOLDS.min_confidence;
  const inDropSeverities = (
    SEVERITY_GATE_THRESHOLDS.drop_severities as readonly string[]
  ).includes(finding.severity);

  return belowConfidenceThreshold && inDropSeverities;
}

// ---------------------------------------------------------------------------
// 2b. Batch severity gate
// ---------------------------------------------------------------------------

/**
 * Applies shouldDropBySeverity to each finding.
 * Returns surviving findings and audit stats.
 */
export function filterBySeverity(findings: RawScannerFinding[]): {
  passed: RawScannerFinding[];
  stats: PreFilterStats;
} {
  const passed: RawScannerFinding[] = [];
  const removedIds: string[] = [];

  for (const finding of findings) {
    if (shouldDropBySeverity(finding)) {
      removedIds.push(finding.id);
    } else {
      passed.push(finding);
    }
  }

  const stats: PreFilterStats = {
    step: "severity_gate",
    input_count: findings.length,
    output_count: passed.length,
    removed_count: removedIds.length,
    removed_ids: removedIds,
  };

  return { passed, stats };
}
