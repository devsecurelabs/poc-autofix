import { z } from 'zod';

// ─── Environment ──────────────────────────────────────────────────────────────

export interface Env {
  AI: Ai;
  DEVSECURE_API_TOKEN: string;
  ENVIRONMENT: string;
  MAX_FINDINGS_PER_REQUEST: string;
  RATE_LIMIT_PER_MINUTE: string;
}

// ─── L1.5 Incoming Types ──────────────────────────────────────────────────────

export type DetectionSignal = 'CONVERGED' | 'PATTERN_ONLY' | 'DATAFLOW_ONLY' | 'NO_DETECTION_ESCALATION';

export interface OriginalFinding {
  source_scanner: string;
  snippet: string;
  rule_id: string;
  [key: string]: unknown;
}

export interface NormalizedFinding {
  dedup_hash: string;
  file_path: string;
  line_start: number;
  line_end: number;
  cwe_id: string;
  cwe_category: string;
  detection_signal: DetectionSignal;
  max_severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  max_confidence: number;
  original_findings: OriginalFinding[];
}

export interface BatchedFilePayload {
  file_path: string;
  code_context: string;
  findings: NormalizedFinding[];
  is_escalation: boolean;
}

export interface L2BatchPayload {
  pr_ref: string;
  commit_sha: string;
  repository: string;
  timestamp: string;
  scanner_versions: { opengrep: string; bearer: string };
  summary: {
    total_files_scanned: number;
    total_raw_findings: number;
    total_after_dedup: number;
    total_after_filters: number;
    total_escalations: number;
  };
  files: BatchedFilePayload[];
}

// ─── L2 Output Types ──────────────────────────────────────────────────────────

export type BlastRadiusLane = 1 | 2 | 3 | 4;

export interface L2FindingClassification {
  finding_hash: string;
  authoritative_cwe_id: string;
  authoritative_cwe_name: string;
  confidence: number;
  blast_radius_lane: BlastRadiusLane;
  verdict: 'ESCALATE' | 'DISMISS' | 'REVIEW';
  detection_signal: DetectionSignal;
  reasoning: string;
}

export interface L2EscalationResult {
  file_path: string;
  heuristic_verdict: 'SUSPICIOUS' | 'CLEAN' | 'UNCERTAIN';
  reasoning: string;
  suggested_cwe: string | null;
}

export interface L2TriageResponse {
  request_id: string;
  timestamp: string;
  pr_ref: string;
  repository: string;
  classifications: L2FindingClassification[];
  escalation_results: L2EscalationResult[];
  processing_time_ms: number;
}

// ─── Zod Schemas ──────────────────────────────────────────────────────────────

const detectionSignalSchema = z.enum(['CONVERGED', 'PATTERN_ONLY', 'DATAFLOW_ONLY', 'NO_DETECTION_ESCALATION']);

const originalFindingSchema = z.object({
  source_scanner: z.string(),
  snippet: z.string(),
  rule_id: z.string(),
}).passthrough();

const normalizedFindingSchema = z.object({
  dedup_hash: z.string().min(1),
  file_path: z.string().min(1),
  line_start: z.number().int().nonnegative(),
  line_end: z.number().int().nonnegative(),
  cwe_id: z.string().min(1),
  cwe_category: z.string().min(1),
  detection_signal: detectionSignalSchema,
  max_severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  max_confidence: z.number().min(0).max(1),
  original_findings: z.array(originalFindingSchema).min(1),
});

const batchedFilePayloadSchema = z.object({
  file_path: z.string().min(1),
  code_context: z.string(),
  findings: z.array(normalizedFindingSchema),
  is_escalation: z.boolean(),
});

export const l2BatchPayloadSchema = z.object({
  pr_ref: z.string().min(1),
  commit_sha: z.string().min(1),
  repository: z.string().min(1),
  timestamp: z.string().datetime(),
  scanner_versions: z.object({
    opengrep: z.string(),
    bearer: z.string(),
  }),
  summary: z.object({
    total_files_scanned: z.number().int().nonnegative(),
    total_raw_findings: z.number().int().nonnegative(),
    total_after_dedup: z.number().int().nonnegative(),
    total_after_filters: z.number().int().nonnegative(),
    total_escalations: z.number().int().nonnegative(),
  }),
  files: z.array(batchedFilePayloadSchema).min(1),
});

export const l2FindingClassificationSchema = z.object({
  finding_hash: z.string().min(1),
  authoritative_cwe_id: z.string().min(1),
  authoritative_cwe_name: z.string().min(1),
  confidence: z.number().min(0).max(1),
  blast_radius_lane: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
  verdict: z.enum(['ESCALATE', 'DISMISS', 'REVIEW']),
  reasoning: z.string().max(300),
});

export const l2EscalationResultSchema = z.object({
  heuristic_verdict: z.enum(['SUSPICIOUS', 'CLEAN', 'UNCERTAIN']),
  reasoning: z.string().max(500),
  suggested_cwe: z.string().nullable(),
});
