// Author: Jeremy Quadri
// src/types.ts — Shared type definitions and Zod schemas for DevSecure v4.0.
// Covers the Adversarial Judge output schema (Requirement 9) and
// the L1 Detection Plane data models (Phase 1).

import { z } from "zod";

// ---------------------------------------------------------------------------
// Detection Signal
// ---------------------------------------------------------------------------

/** How L1 scanners detected the original finding. */
export type DetectionSignal =
  | "CONVERGED"
  | "PATTERN_ONLY"
  | "DATAFLOW_ONLY"
  | "NO_DETECTION_ESCALATION";

// ---------------------------------------------------------------------------
// Judge Evaluation Input
// ---------------------------------------------------------------------------

/** Full context the adversarial judge receives to evaluate a proposed patch. */
export interface JudgeEvaluationInput {
  /** The proposed fix as a unified diff. */
  patch_diff: string;
  /** Original scanner finding that triggered the pipeline. */
  original_finding: {
    cwe_id: string;          // e.g. "CWE-89"
    cwe_name: string;        // e.g. "SQL Injection"
    description: string;     // Scanner's description of the finding
    file_path: string;       // File where the vulnerability was found
    line_start: number;
    line_end: number;
    source_scanner: string;  // "opengrep" | "bearer"
  };
  detection_signal: DetectionSignal;
  /** File being patched (may differ from finding file in multi-file scenarios). */
  file_path: string;
}

// ---------------------------------------------------------------------------
// Risk Flags
// ---------------------------------------------------------------------------

/** Well-known risk flags with autocomplete support. */
export type KnownRiskFlag =
  | "logic_change"
  | "auth_change"
  | "boundary_change"
  | "dataflow_change"
  | "incomplete_fix";

/**
 * Extensible risk flag type — known values get autocomplete,
 * but any string is accepted for novel flags.
 */
// eslint-disable-next-line @typescript-eslint/ban-types
export type RiskFlag = KnownRiskFlag | (string & {});

// ---------------------------------------------------------------------------
// Judge Evaluation (output)
// ---------------------------------------------------------------------------

/** The adversarial judge's structured evaluation of a proposed patch. */
export interface JudgeEvaluation {
  verdict: "PASS" | "FAIL" | "UNCERTAIN";
  confidence: number;       // 0.0 to 1.0
  risk_flags: RiskFlag[];   // Non-empty array
  evidence: string;         // Max 500 chars
  comments: string;         // Max 2000 chars
}

// ---------------------------------------------------------------------------
// Routing Tags and Result
// ---------------------------------------------------------------------------

/** All possible routing outcomes after judge evaluation. */
export type RoutingTag =
  | "AUTO_MERGE"
  | "SOFT_PASS_REVIEW"
  | "JUDGE_REJECTED"
  | "SENIOR_REVIEW_REQUIRED"
  | "STANDARD_REVIEW"
  | "LOW_CONFIDENCE_PASS";

/** Ticket payload for GitHub Issue / Jira creation. */
export interface TicketPayload {
  title: string;                    // e.g. "[JUDGE_REJECTED] CWE-89 in api/users.ts"
  severity: "critical" | "high" | "medium" | "low";
  risk_flags: RiskFlag[];
  evidence: string;
  comments: string;
  detection_signal: DetectionSignal;
  source_file: string;
  cwe_id: string;
  routing_tag: RoutingTag;
  markdown_body: string;            // Pre-rendered Markdown for direct attachment
}

/** Final routing decision returned by routeJudgeResult. */
export interface RoutingResult {
  action: RoutingTag;
  evaluation: JudgeEvaluation;
  ticket_payload: TicketPayload | null;  // null only for AUTO_MERGE
}

// ---------------------------------------------------------------------------
// Zod Schema — runtime validation of JudgeEvaluation
// ---------------------------------------------------------------------------

/** Runtime schema for JudgeEvaluation — used in evaluateWithJudge after JSON.parse. */
export const judgeEvaluationSchema = z.object({
  verdict:    z.enum(["PASS", "FAIL", "UNCERTAIN"]),
  confidence: z.number().min(0).max(1),
  risk_flags: z.array(z.string()).nonempty(),
  evidence:   z.string().max(500),
  comments:   z.string().max(2000),
});

// ===========================================================================
// L1 Detection Plane — Phase 1 Data Models (interfaces + Zod schemas)
// ===========================================================================

// ---------------------------------------------------------------------------
// 2a. RawScannerFinding — single finding as emitted by either scanner
// ---------------------------------------------------------------------------

/** A single vulnerability finding as output by either scanner before any L1 processing. */
export interface RawScannerFinding {
  id:             string;
  source_scanner: "opengrep" | "bearer";
  file_path:      string;
  line_start:     number;
  line_end:       number;
  cwe_id:         string;                    // Specific CWE e.g. "CWE-89"
  cwe_category:   string;                    // Grouping e.g. "injection" — for dedup matching
  rule_id:        string;                    // Scanner-specific rule identifier
  severity:       "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence:     number;                    // 0.0 to 1.0, scanner's own confidence
  snippet:        string;                    // Surrounding code context
  snippet_hash:   string;                    // Hash of normalised snippet for dedup
  metadata:       Record<string, unknown>;   // Scanner-specific extra data
}

/** Runtime schema for RawScannerFinding. */
export const rawScannerFindingSchema = z.object({
  id:             z.string().min(1),
  source_scanner: z.enum(["opengrep", "bearer"]),
  file_path:      z.string().min(1),
  line_start:     z.number().int().nonnegative(),
  line_end:       z.number().int().nonnegative(),
  cwe_id:         z.string().min(1),
  cwe_category:   z.string().min(1),
  rule_id:        z.string().min(1),
  severity:       z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  confidence:     z.number().min(0).max(1),
  snippet:        z.string().min(1),
  snippet_hash:   z.string().min(1),
  metadata:       z.record(z.string(), z.unknown()),
});

// ---------------------------------------------------------------------------
// 2b. SuppressionEntry — Per Requirement 5 (Allowlist)
// ---------------------------------------------------------------------------

/** A single entry in the suppression / allowlist file (Requirement 5). */
export interface SuppressionEntry {
  rule_id:     string | null;   // null means match any rule
  cwe_id:      string | null;   // null means match any CWE
  file_pattern: string;         // Glob pattern e.g. "tests/fixtures/**"
  reason:      string;
  approved_by: string;          // e.g. "@security-lead"
  expires_at:  string | null;   // ISO date string, null means no expiry
  created_at:  string;          // ISO date string
}

/** Runtime schema for SuppressionEntry. */
export const suppressionEntrySchema = z.object({
  rule_id:      z.string().nullable(),
  cwe_id:       z.string().nullable(),
  file_pattern: z.string().min(1),
  reason:       z.string().min(1),
  approved_by:  z.string().min(1),
  expires_at:   z.string().datetime().nullable(),
  created_at:   z.string().datetime(),
});

// ---------------------------------------------------------------------------
// 2c. NormalizedFinding — finding after deduplication and signal assignment
// ---------------------------------------------------------------------------

/** A finding after deduplication, signal assignment, and severity normalisation. */
export interface NormalizedFinding {
  dedup_hash:        string;                                       // Composite hash for dedup matching
  file_path:         string;
  line_start:        number;
  line_end:          number;
  cwe_id:            string;                                       // Specific CWE from highest-confidence source
  cwe_category:      string;                                       // Category grouping for dedup
  detection_signal:  DetectionSignal;                              // Reuse existing type from Requirement 9
  max_severity:      "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; // Highest severity from merged findings
  max_confidence:    number;                                       // Highest confidence from merged findings
  original_findings: RawScannerFinding[];                          // The 1 or 2 raw findings that were merged
}

/** Runtime schema for NormalizedFinding. */
export const normalizedFindingSchema = z.object({
  dedup_hash:        z.string().min(1),
  file_path:         z.string().min(1),
  line_start:        z.number().int().nonnegative(),
  line_end:          z.number().int().nonnegative(),
  cwe_id:            z.string().min(1),
  cwe_category:      z.string().min(1),
  detection_signal:  z.enum(["CONVERGED", "PATTERN_ONLY", "DATAFLOW_ONLY", "NO_DETECTION_ESCALATION"]),
  max_severity:      z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  max_confidence:    z.number().min(0).max(1),
  original_findings: z.array(rawScannerFindingSchema).min(1),
});

// ---------------------------------------------------------------------------
// 2d. BatchedFilePayload — Per Requirement 7, one file's findings for L2 batch
// ---------------------------------------------------------------------------

/**
 * One file's worth of findings for the L2 batch (Requirement 7).
 * INVARIANT: if is_escalation is false, findings must be non-empty.
 */
export interface BatchedFilePayload {
  file_path:    string;
  code_context: string;                 // Relevant diff or file content
  findings:     NormalizedFinding[];
  is_escalation: boolean;              // true = Requirement 10 No-Detection Escalation
}

/** Runtime schema for BatchedFilePayload. Enforces the non-escalation/non-empty invariant. */
export const batchedFilePayloadSchema = z.object({
  file_path:    z.string().min(1),
  code_context: z.string(),
  findings:     z.array(normalizedFindingSchema),
  is_escalation: z.boolean(),
}).refine(
  (data) => data.is_escalation || data.findings.length > 0,
  { message: "Non-escalation payloads must contain at least one finding" },
);

// ---------------------------------------------------------------------------
// 2e. L2BatchPayload — top-level wrapper sent as a single POST to L2 Worker
// ---------------------------------------------------------------------------

/** Top-level payload sent as a single POST to the L2 Cloudflare Worker. */
export interface L2BatchPayload {
  pr_ref:     string;          // e.g. "refs/pull/142"
  commit_sha: string;
  repository: string;          // e.g. "org/repo-name"
  timestamp:  string;          // ISO date string
  scanner_versions: {
    opengrep: string;
    bearer:   string;
  };
  summary: {
    total_files_scanned:   number;
    total_raw_findings:    number;    // Before any filtering
    total_after_dedup:     number;
    total_after_filters:   number;    // After all L1.5 pre-filtering
    total_escalations:     number;    // Requirement 10 escalations
  };
  files: BatchedFilePayload[];
}

/** Runtime schema for L2BatchPayload. */
export const l2BatchPayloadSchema = z.object({
  pr_ref:     z.string().min(1),
  commit_sha: z.string().min(1),
  repository: z.string().min(1),
  timestamp:  z.string().datetime(),
  scanner_versions: z.object({
    opengrep: z.string().min(1),
    bearer:   z.string().min(1),
  }),
  summary: z.object({
    total_files_scanned: z.number().int().nonnegative(),
    total_raw_findings:  z.number().int().nonnegative(),
    total_after_dedup:   z.number().int().nonnegative(),
    total_after_filters: z.number().int().nonnegative(),
    total_escalations:   z.number().int().nonnegative(),
  }),
  files: z.array(batchedFilePayloadSchema).min(1),
});

// ---------------------------------------------------------------------------
// 2f. PreFilterStats — tracking per-step filter counts (Requirement 8)
// ---------------------------------------------------------------------------

/** Per-step filter tracking for the Requirement 8 feedback loop. */
export interface PreFilterStats {
  step:          "scope_lock" | "diff_only" | "dedup" | "path_filter" | "allowlist" | "severity_gate" | "content_type_check";
  input_count:   number;
  output_count:  number;
  removed_count: number;
  removed_ids:   string[];   // IDs of findings removed at this step
}

/** Runtime schema for PreFilterStats. Enforces removed_count arithmetic invariant. */
export const preFilterStatsSchema = z.object({
  step:          z.enum(["scope_lock", "diff_only", "dedup", "path_filter", "allowlist", "severity_gate", "content_type_check"]),
  input_count:   z.number().int().nonnegative(),
  output_count:  z.number().int().nonnegative(),
  removed_count: z.number().int().nonnegative(),
  removed_ids:   z.array(z.string()),
}).refine(
  (data) => data.removed_count === data.input_count - data.output_count,
  { message: "removed_count must equal input_count minus output_count" },
);
