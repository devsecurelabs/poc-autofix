// Author: Jeremy Quadri
// src/filters/escalation.ts — No-Detection Escalation for high-risk code (Requirement 10).

import { HIGH_RISK_FILE_PATTERNS } from "../constants";
import type { NormalizedFinding, BatchedFilePayload } from "../types";

// ---------------------------------------------------------------------------
// 5a. High-risk file check
// ---------------------------------------------------------------------------

/**
 * Returns true if the file path (lowercased) contains any string from
 * HIGH_RISK_FILE_PATTERNS.
 */
export function isHighRiskFile(filePath: string): boolean {
  const lower = filePath.toLowerCase().replace(/\\/g, "/");
  return (HIGH_RISK_FILE_PATTERNS as readonly string[]).some((pattern) =>
    lower.includes(pattern),
  );
}

// ---------------------------------------------------------------------------
// 5b. No-detection escalation check
// ---------------------------------------------------------------------------

/**
 * For each changed file that is high-risk and has NO existing findings,
 * generates an escalation BatchedFilePayload.
 *
 * Returns an array of escalation payloads (may be empty).
 */
export function checkNoDetectionEscalation(
  changedFiles: string[],
  findings: NormalizedFinding[],
): BatchedFilePayload[] {
  const escalations: BatchedFilePayload[] = [];

  // Build a set of file paths that already have findings
  const coveredFiles = new Set(
    findings.map((f) => f.file_path.replace(/\\/g, "/").toLowerCase()),
  );

  for (const file of changedFiles) {
    if (!isHighRiskFile(file)) continue;

    const normFile = file.replace(/\\/g, "/").toLowerCase();
    if (coveredFiles.has(normFile)) continue;

    escalations.push({
      file_path:     file,
      code_context:  "",
      findings:      [],
      is_escalation: true,
    });
  }

  return escalations;
}
