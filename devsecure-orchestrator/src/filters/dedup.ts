// Author: Jeremy Quadri
// src/filters/dedup.ts — Deduplication with robust matching (Requirement 3).

import { createHash } from "crypto";
import { DEDUP_PROXIMITY_LINES } from "../constants";
import type {
  RawScannerFinding,
  NormalizedFinding,
  DetectionSignal,
  PreFilterStats,
} from "../types";

// ---------------------------------------------------------------------------
// Severity ordering for max_severity selection
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  INFO:     0,
  LOW:      1,
  MEDIUM:   2,
  HIGH:     3,
  CRITICAL: 4,
};

// ---------------------------------------------------------------------------
// 4a. Dedup hash
// ---------------------------------------------------------------------------

/**
 * Computes a dedup hash from normalised file_path + cwe_category + snippet_hash.
 */
export function computeDedupHash(finding: RawScannerFinding): string {
  const normPath = finding.file_path
    .replace(/\\/g, "/")
    .toLowerCase()
    .replace(/^\.\//, "")
    .replace(/^\//, "");

  const input = `${normPath}::${finding.cwe_category}::${finding.snippet_hash}`;
  return createHash("sha256").update(input).digest("hex");
}

// ---------------------------------------------------------------------------
// 4b. Likely-duplicate check
// ---------------------------------------------------------------------------

/**
 * Returns true when two findings are likely referring to the same vulnerability.
 * All four conditions must hold.
 */
export function areLikelyDuplicates(
  a: RawScannerFinding,
  b: RawScannerFinding,
): boolean {
  const normA = a.file_path.replace(/\\/g, "/").toLowerCase().replace(/^\.\//, "");
  const normB = b.file_path.replace(/\\/g, "/").toLowerCase().replace(/^\.\//, "");

  if (normA !== normB) return false;
  if (a.cwe_category !== b.cwe_category) return false;
  if (Math.abs(a.line_start - b.line_start) > DEDUP_PROXIMITY_LINES) return false;
  if (a.snippet_hash === b.snippet_hash) return true;
  if (computeDedupHash(a) === computeDedupHash(b)) return true;

  return false;
}

// ---------------------------------------------------------------------------
// 4c. Detection signal assignment
// ---------------------------------------------------------------------------

/**
 * Determines the detection signal from the set of merged findings.
 * Never called with an empty array.
 */
export function assignDetectionSignal(
  mergedFindings: RawScannerFinding[],
): DetectionSignal {
  const hasOpengrep = mergedFindings.some((f) => f.source_scanner === "opengrep");
  const hasBearer   = mergedFindings.some((f) => f.source_scanner === "bearer");

  if (hasOpengrep && hasBearer) return "CONVERGED";
  if (hasBearer)                return "DATAFLOW_ONLY";
  return "PATTERN_ONLY";
}

// ---------------------------------------------------------------------------
// 4d. Full deduplication pass
// ---------------------------------------------------------------------------

/**
 * Merges findings that refer to the same underlying vulnerability into
 * NormalizedFinding objects. Returns deduplicated findings and audit stats.
 */
export function deduplicateFindings(findings: RawScannerFinding[]): {
  deduplicated: NormalizedFinding[];
  stats: PreFilterStats;
} {
  // Group by file_path for efficiency
  const byFile = new Map<string, RawScannerFinding[]>();
  for (const finding of findings) {
    const key = finding.file_path.replace(/\\/g, "/").toLowerCase();
    const group = byFile.get(key) ?? [];
    group.push(finding);
    byFile.set(key, group);
  }

  const deduplicated: NormalizedFinding[] = [];

  for (const [, group] of byFile) {
    const clusters = clusterFindings(group);

    for (const cluster of clusters) {
      const best = highestConfidence(cluster);

      const maxSeverityFinding = cluster.reduce((acc, f) =>
        (SEVERITY_ORDER[f.severity] ?? 0) > (SEVERITY_ORDER[acc.severity] ?? 0)
          ? f
          : acc,
      );

      const normalised: NormalizedFinding = {
        dedup_hash:        computeDedupHash(cluster[0]),
        file_path:         best.file_path,
        line_start:        best.line_start,
        line_end:          best.line_end,
        cwe_id:            best.cwe_id,
        cwe_category:      cluster[0].cwe_category,
        detection_signal:  assignDetectionSignal(cluster),
        max_severity:      maxSeverityFinding.severity,
        max_confidence:    Math.max(...cluster.map((f) => f.confidence)),
        original_findings: cluster,
      };

      deduplicated.push(normalised);
    }
  }

  const stats: PreFilterStats = {
    step:          "dedup",
    input_count:   findings.length,
    output_count:  deduplicated.length,
    removed_count: findings.length - deduplicated.length,
    removed_ids:   [], // Individual raw finding IDs don't map cleanly to removed; we track at cluster level
  };

  return { deduplicated, stats };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Clusters findings within a file group using a greedy union-find approach.
 */
function clusterFindings(findings: RawScannerFinding[]): RawScannerFinding[][] {
  const assigned = new Array<boolean>(findings.length).fill(false);
  const clusters: RawScannerFinding[][] = [];

  for (let i = 0; i < findings.length; i++) {
    if (assigned[i]) continue;

    const cluster: RawScannerFinding[] = [findings[i]];
    assigned[i] = true;

    for (let j = i + 1; j < findings.length; j++) {
      if (assigned[j]) continue;
      // Check if j is a duplicate of ANY finding already in the cluster
      for (const existing of cluster) {
        if (areLikelyDuplicates(existing, findings[j])) {
          cluster.push(findings[j]);
          assigned[j] = true;
          break;
        }
      }
    }

    clusters.push(cluster);
  }

  return clusters;
}

/** Returns the finding with the highest confidence from a cluster. */
function highestConfidence(cluster: RawScannerFinding[]): RawScannerFinding {
  return cluster.reduce((acc, f) => (f.confidence > acc.confidence ? f : acc));
}
