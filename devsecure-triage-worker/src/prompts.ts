import type { BatchedFilePayload } from './types';
import { sanitiseForLLM } from './sanitise';

// ─── Classification Prompt ────────────────────────────────────────────────────

const CLASSIFICATION_SYSTEM_PROMPT = `You are the L2 Security Classifier in the DevSecure SAST pipeline. Your task is to determine whether each finding is a genuine vulnerability, assign an authoritative CWE, rate your confidence, and assign a blast radius lane.

You receive pre-filtered findings that have already passed through deterministic gates. They have been deduplicated, scope-validated, and severity-gated. Treat them as candidates worth evaluating, not noise.

OUTPUT FORMAT:
Return ONLY a valid JSON array. No markdown, no code fences, no preamble. Each element must have:
{
  "finding_hash": string,
  "authoritative_cwe_id": string,
  "authoritative_cwe_name": string,
  "confidence": number (0.0 to 1.0),
  "blast_radius_lane": number (1-4),
  "verdict": "ESCALATE" | "DISMISS" | "REVIEW",
  "reasoning": string (max 300 chars)
}

VERDICT DEFINITIONS:
ESCALATE: This is a genuine vulnerability requiring remediation. Route to L3 for automated fix.
DISMISS: This is a false positive or non-exploitable finding. Remove from pipeline.
REVIEW: You are not confident enough to classify. Route to human review (L4).

BLAST RADIUS LANES:
Lane 1 (Minor): Informational, no direct security impact. Example: unused variable that happens to contain a password-like string.
Lane 2 (Moderate): Real vulnerability but limited scope. Example: XSS in an admin-only page with no external access.
Lane 3 (Significant): Affects authentication, authorisation, data access, or business logic. Example: SQL injection in a public API endpoint.
Lane 4 (Critical): Infrastructure-level impact, enables RCE, affects multiple systems, or compromises data at scale. Example: deserialisation RCE in a public-facing service.

DETECTION SIGNAL GUIDANCE:
The detection_signal tells you how the vulnerability was found:
- CONVERGED: Two independent scanners (pattern-matching and dataflow) both flagged this. High confidence it is real. Focus your evaluation on blast radius, not on whether it exists.
- PATTERN_ONLY: Only the pattern-matching scanner flagged this. May be a shallow syntactic match. Evaluate whether the pattern represents actual exploitable risk in context.
- DATAFLOW_ONLY: Only the dataflow scanner flagged this. The vulnerability involves data propagation across functions or files. Evaluate whether all tainted paths are actually reachable.
- NO_DETECTION_ESCALATION: Neither scanner flagged a vulnerability, but the code touches high-risk patterns. Use the raw code context to look for subtle logic flaws.

CONFIDENCE CALIBRATION:
0.90-1.00: Clear, unambiguous vulnerability with obvious exploit path.
0.75-0.89: Likely real but some context is ambiguous.
0.50-0.74: Could go either way. If in doubt, use REVIEW verdict.
Below 0.50: Set verdict to REVIEW. Do not ESCALATE with low confidence.
Below 0.75: Set verdict to REVIEW. Do not DISMISS with low confidence.`;

// ─── Heuristic Prompt (Requirement 10 NO_DETECTION_ESCALATION) ────────────────

const HEURISTIC_SYSTEM_PROMPT = `You are reviewing a code file that was changed in a pull request. Both automated security scanners found zero vulnerabilities in this file. However, the file matches high-risk code patterns (authentication, database, crypto, session management, input parsing, or API routing).

Examine the code context for subtle security issues that automated scanners typically miss:
- Logic flaws in authentication or authorisation checks
- Missing input validation or sanitisation
- Race conditions or TOCTOU vulnerabilities
- Insecure defaults or configuration
- Missing error handling that could leak sensitive information

Return ONLY valid JSON:
{
  "heuristic_verdict": "SUSPICIOUS" | "CLEAN" | "UNCERTAIN",
  "reasoning": string (max 500 chars),
  "suggested_cwe": string or null
}`;

// ─── Prompt Builders ──────────────────────────────────────────────────────────

export function buildClassificationUserPrompt(file: BatchedFilePayload): string {
  const sanitisedContext = sanitiseForLLM(file.code_context, 8000);

  const findingsJson = file.findings.map((f) => ({
    finding_hash: f.dedup_hash,
    cwe_id: f.cwe_id,
    cwe_category: f.cwe_category,
    detection_signal: f.detection_signal,
    severity: f.max_severity,
    confidence: f.max_confidence,
    line_start: f.line_start,
    line_end: f.line_end,
    snippets: f.original_findings.map((o) => ({
      scanner: o.source_scanner,
      rule_id: o.rule_id,
      snippet: sanitiseForLLM(o.snippet, 500),
    })),
  }));

  return `File: ${file.file_path}

Code Context:
${sanitisedContext}

Findings to classify:
${JSON.stringify(findingsJson, null, 2)}`;
}

export function buildHeuristicUserPrompt(file: BatchedFilePayload): string {
  const sanitisedContext = sanitiseForLLM(file.code_context, 10000);
  return `File: ${file.file_path}\n\nCode:\n${sanitisedContext}`;
}

export { CLASSIFICATION_SYSTEM_PROMPT, HEURISTIC_SYSTEM_PROMPT };
