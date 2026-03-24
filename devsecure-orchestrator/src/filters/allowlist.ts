// Author: Jeremy Quadri
// src/filters/allowlist.ts — Allowlist and suppression filtering (Requirement 5).

import type { RawScannerFinding, SuppressionEntry, PreFilterStats } from "../types";

// ---------------------------------------------------------------------------
// 3a. Single-finding suppression check
// ---------------------------------------------------------------------------

/**
 * Returns true if any non-expired suppression in the list matches the finding.
 *
 * A suppression matches when ALL non-null fields match:
 *   - rule_id (if not null): exact match with finding.rule_id
 *   - cwe_id  (if not null): exact match with finding.cwe_id
 *   - file_pattern:          glob match against finding.file_path
 *
 * Expired suppressions (expires_at < now) are ignored.
 */
export function isSuppressed(
  finding: RawScannerFinding,
  suppressions: SuppressionEntry[],
): boolean {
  const now = new Date();

  for (const suppression of suppressions) {
    // Expiry check — skip expired suppressions
    if (
      suppression.expires_at !== null &&
      new Date(suppression.expires_at) < now
    ) {
      continue;
    }

    // rule_id match (if specified)
    if (
      suppression.rule_id !== null &&
      suppression.rule_id !== finding.rule_id
    ) {
      continue;
    }

    // cwe_id match (if specified)
    if (
      suppression.cwe_id !== null &&
      suppression.cwe_id !== finding.cwe_id
    ) {
      continue;
    }

    // file_pattern glob match
    if (!matchesFilePattern(finding.file_path, suppression.file_pattern)) {
      continue;
    }

    return true;
  }

  return false;
}

/**
 * Matches a file path against a glob pattern.
 *
 * Rules:
 *   - Pattern contains '**': path must contain the prefix before '**'
 *   - Pattern contains '*': wildcard match
 *   - Otherwise: exact string match
 */
function matchesFilePattern(filePath: string, pattern: string): boolean {
  const normPath = filePath.replace(/\\/g, "/");
  const normPattern = pattern.replace(/\\/g, "/");

  if (normPattern.includes("**")) {
    // Use the prefix before '**' as a path-contains check
    const prefix = normPattern.split("**")[0].replace(/\/$/, "");
    return normPath.includes(prefix);
  }

  if (normPattern.includes("*")) {
    // Convert glob to regex: escape dots, replace * with [^/]*
    const regexStr = normPattern
      .split("*")
      .map((part) => part.replace(/[.+^${}()|[\]\\]/g, "\\$&"))
      .join("[^/]*");
    const regex = new RegExp(regexStr);
    return regex.test(normPath);
  }

  // Exact match
  return normPath === normPattern || normPath.endsWith("/" + normPattern);
}

// ---------------------------------------------------------------------------
// 3b. Batch allowlist filter
// ---------------------------------------------------------------------------

/**
 * Filters findings against the suppression list.
 * Returns surviving findings and audit stats.
 */
export function filterByAllowlist(
  findings: RawScannerFinding[],
  suppressions: SuppressionEntry[],
): {
  passed: RawScannerFinding[];
  stats: PreFilterStats;
} {
  const passed: RawScannerFinding[] = [];
  const removedIds: string[] = [];

  for (const finding of findings) {
    if (isSuppressed(finding, suppressions)) {
      removedIds.push(finding.id);
    } else {
      passed.push(finding);
    }
  }

  const stats: PreFilterStats = {
    step: "allowlist",
    input_count: findings.length,
    output_count: passed.length,
    removed_count: removedIds.length,
    removed_ids: removedIds,
  };

  return { passed, stats };
}
