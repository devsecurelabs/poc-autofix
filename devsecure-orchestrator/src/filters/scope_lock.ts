// Author: Jeremy Quadri
// src/filters/scope_lock.ts — Scope Lock: Requirement 1 (Scanner Scope Validation).
// Drops any finding referencing a file not in the current PR diff.
// This is a fail-closed secondary defense — we do not trust scanner scope config.

import type { RawScannerFinding, PreFilterStats } from "../types";

// ---------------------------------------------------------------------------
// 1b. Path normalisation helper
// ---------------------------------------------------------------------------

/** Known repository root segments used to strip absolute path prefixes. */
const ROOT_SEGMENTS = ["src/", "lib/", "app/", "packages/"];

/**
 * Normalises a file path for case-insensitive, cross-platform scope comparison.
 *
 * Steps applied in order:
 *   1. Replace backslashes with forward slashes
 *   2. Remove leading './' or '/'
 *   3. Strip any absolute prefix up to the first known repo-root segment
 *      (src/, lib/, app/, packages/). If none found, use the path as-is.
 *   4. Lowercase
 */
export function normalizePath(filePath: string): string {
  // Step 1 — normalise separators
  let p = filePath.replace(/\\/g, "/");

  // Step 2 — strip leading ./ or /
  p = p.replace(/^\.\//, "").replace(/^\/+/, "");

  // Step 3 — strip absolute prefix up to first known root segment
  for (const seg of ROOT_SEGMENTS) {
    const idx = p.indexOf(seg);
    if (idx > 0) {
      // idx > 0 means there IS a prefix before the segment to strip
      p = p.slice(idx);
      break;
    }
  }

  // Step 4 — lowercase
  return p.toLowerCase();
}

// ---------------------------------------------------------------------------
// 1c. Batch scope lock filter
// ---------------------------------------------------------------------------

/**
 * Drops findings whose file_path is not in the PR's changed files set.
 *
 * Fail-closed: if changedFiles is empty, ALL findings are dropped.
 */
export function filterByScope(
  findings: RawScannerFinding[],
  changedFiles: string[],
): {
  passed: RawScannerFinding[];
  stats: PreFilterStats;
} {
  // Build normalised lookup set — O(1) per finding
  const scopeSet = new Set(changedFiles.map(normalizePath));

  const passed: RawScannerFinding[] = [];
  const removedIds: string[] = [];

  for (const finding of findings) {
    if (scopeSet.has(normalizePath(finding.file_path))) {
      passed.push(finding);
    } else {
      removedIds.push(finding.id);
    }
  }

  const stats: PreFilterStats = {
    step:          "scope_lock",
    input_count:   findings.length,
    output_count:  passed.length,
    removed_count: removedIds.length,
    removed_ids:   removedIds,
  };

  return { passed, stats };
}
