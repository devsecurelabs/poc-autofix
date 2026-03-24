// Author: Jeremy Quadri
// src/filters/pipeline.ts — L1.5 Pre-Filter pipeline orchestrator (Requirement 8).
// Chains all filter steps in the correct Board-approved order:
//   scope_lock -> path -> allowlist -> severity -> dedup -> escalation

import { filterByScope }        from "./scope_lock";
import { filterByPath }         from "./path_filter";
import { filterByAllowlist }    from "./allowlist";
import { filterBySeverity }     from "./severity_gate";
import { deduplicateFindings }  from "./dedup";
import { checkNoDetectionEscalation } from "./escalation";
import { l2BatchPayloadSchema } from "../types";

import type {
  RawScannerFinding,
  NormalizedFinding,
  BatchedFilePayload,
  PreFilterStats,
  SuppressionEntry,
  L2BatchPayload,
} from "../types";

// ---------------------------------------------------------------------------
// 6a. Pipeline orchestrator
// ---------------------------------------------------------------------------

/**
 * Executes the full L1.5 pre-filter pipeline in the mandated order.
 * Each step returns its survivors and an audit PreFilterStats object.
 *
 * Order: path -> allowlist -> severity -> dedup -> escalation (Req 10)
 */
export async function runPreFilterPipeline(input: {
  raw_findings:  RawScannerFinding[];
  changed_files: string[];
  suppressions:  SuppressionEntry[];
}): Promise<{
  normalized_findings:  NormalizedFinding[];
  escalation_payloads:  BatchedFilePayload[];
  pipeline_stats:       PreFilterStats[];
  total_input:          number;
  total_output:         number;
}> {
  const pipeline_stats: PreFilterStats[] = [];

  // STEP A — Scope Lock (Requirement 1): fail-closed guard; must be first
  const scopeResult = filterByScope(input.raw_findings, input.changed_files);
  pipeline_stats.push(scopeResult.stats);

  // STEP B — Path Filtering (Requirement 4)
  const pathResult = filterByPath(scopeResult.passed);
  pipeline_stats.push(pathResult.stats);

  // STEP C — Allowlist Filtering (Requirement 5)
  const allowlistResult = filterByAllowlist(pathResult.passed, input.suppressions);
  pipeline_stats.push(allowlistResult.stats);

  // STEP C — Severity Gating (Requirement 6)
  const severityResult = filterBySeverity(allowlistResult.passed);
  pipeline_stats.push(severityResult.stats);

  // STEP D — Deduplication (Requirement 3)
  const dedupResult = deduplicateFindings(severityResult.passed);
  pipeline_stats.push(dedupResult.stats);

  // STEP E — No-Detection Escalation (Requirement 10)
  const escalation_payloads = checkNoDetectionEscalation(
    input.changed_files,
    dedupResult.deduplicated,
  );

  const normalized_findings = dedupResult.deduplicated;

  return {
    normalized_findings,
    escalation_payloads,
    pipeline_stats,
    total_input:  input.raw_findings.length,
    total_output: normalized_findings.length + escalation_payloads.length,
  };
}

// ---------------------------------------------------------------------------
// 6b. L2BatchPayload builder
// ---------------------------------------------------------------------------

/**
 * Assembles a validated L2BatchPayload from pipeline output.
 * Groups normalized_findings by file_path and merges escalation payloads.
 * Throws if the assembled payload fails Zod validation.
 */
export function buildL2BatchPayload(input: {
  pr_ref:               string;
  commit_sha:           string;
  repository:           string;
  scanner_versions:     { opengrep: string; bearer: string };
  normalized_findings:  NormalizedFinding[];
  escalation_payloads:  BatchedFilePayload[];
  pipeline_stats:       PreFilterStats[];
  total_raw:            number;
}): L2BatchPayload {
  // Group findings by file_path
  const byFile = new Map<string, NormalizedFinding[]>();
  for (const finding of input.normalized_findings) {
    const group = byFile.get(finding.file_path) ?? [];
    group.push(finding);
    byFile.set(finding.file_path, group);
  }

  const findingPayloads: BatchedFilePayload[] = Array.from(byFile.entries()).map(
    ([file_path, findings]) => ({
      file_path,
      code_context:  "",
      findings,
      is_escalation: false,
    }),
  );

  const files = [...findingPayloads, ...input.escalation_payloads];

  // Compute summary counts from pipeline_stats
  const totalAfterDedup = getOutputCount(input.pipeline_stats, "dedup");
  const totalAfterFilters = getOutputCount(input.pipeline_stats, "severity_gate");

  const payload: L2BatchPayload = {
    pr_ref:           input.pr_ref,
    commit_sha:       input.commit_sha,
    repository:       input.repository,
    timestamp:        new Date().toISOString(),
    scanner_versions: input.scanner_versions,
    summary: {
      total_files_scanned:   files.length,
      total_raw_findings:    input.total_raw,
      total_after_dedup:     totalAfterDedup,
      total_after_filters:   totalAfterFilters,
      total_escalations:     input.escalation_payloads.length,
    },
    files,
  };

  const validation = l2BatchPayloadSchema.safeParse(payload);
  if (!validation.success) {
    console.error("[buildL2BatchPayload] Validation failed:", validation.error);
    throw new Error(`L2BatchPayload validation failed: ${validation.error.message}`);
  }

  return validation.data;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function getOutputCount(stats: PreFilterStats[], step: PreFilterStats["step"]): number {
  return stats.find((s) => s.step === step)?.output_count ?? 0;
}
