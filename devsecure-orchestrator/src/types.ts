// Author: Jeremy Quadri
// src/types.ts — Shared type definitions and Zod schemas for DevSecure v4.0.
// Covers the Adversarial Judge output schema (Requirement 9).

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
