/**
 * DevSecure L2 Triage Worker
 * Cloudflare Worker — L2 Classification Plane
 *
 * Receives pre-filtered SAST findings from the L1.5 Orchestrator,
 * classifies each finding using an AI model, and returns authoritative
 * CWE classifications with confidence scores and blast radius assignments.
 *
 * This Worker handles ONLY L2 classification (triage).
 * It does NOT generate fixes (L3) or evaluate patches (Judge).
 *
 * Local test command:
 * curl -X POST http://localhost:8787/triage \
 *   -H "Authorization: Bearer test-token-123" \
 *   -H "Content-Type: application/json" \
 *   -d @test_payload.json
 */

import type {
  Env,
  L2FindingClassification,
  L2EscalationResult,
  L2TriageResponse,
  BatchedFilePayload,
} from './types';
import {
  l2BatchPayloadSchema,
  l2FindingClassificationSchema,
  l2EscalationResultSchema,
} from './types';
import { authenticateRequest, RateLimiter } from './middleware';
import {
  CLASSIFICATION_SYSTEM_PROMPT,
  HEURISTIC_SYSTEM_PROMPT,
  buildClassificationUserPrompt,
  buildHeuristicUserPrompt,
} from './prompts';

// ─── Constants ────────────────────────────────────────────────────────────────

const AI_MODEL = '@cf/qwen/qwen2.5-coder-32b-instruct';

// ─── AI Response Extraction ───────────────────────────────────────────────────

/**
 * Extracts a JSON array or object from a raw AI response string.
 *
 * Qwen 2.5 (and most LLMs) often wrap JSON in markdown fences or prepend
 * conversational preamble. This function handles both cases:
 *   1. Prefer content inside ```json ... ``` or ``` ... ``` fences.
 *   2. Fall back to scanning for the first bracket pair that matches the
 *      requested type ('[' for arrays, '{' for objects).
 *
 * Returns the extracted substring, or the original text if nothing matches
 * (letting JSON.parse produce the error with useful context).
 */
function extractJsonFromAIResponse(rawText: string, type: 'array' | 'object'): string {
  // 1. Try markdown fence extraction (handles ```json, ```JSON, ``` etc.)
  const fenceMatch = rawText.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/i);
  if (fenceMatch?.[1]) {
    return fenceMatch[1].trim();
  }

  // 2. Fall back to bracket scanning — find the outermost matching pair
  const open = type === 'array' ? '[' : '{';
  const close = type === 'array' ? ']' : '}';
  const start = rawText.indexOf(open);
  const end = rawText.lastIndexOf(close);
  if (start !== -1 && end > start) {
    return rawText.slice(start, end + 1).trim();
  }

  // 3. Return as-is so JSON.parse gives a useful error
  return rawText.trim();
}

// ─── Module-level rate limiter (persists across requests in the same isolate) ──

let rateLimiter: RateLimiter | null = null;

function getRateLimiter(env: Env): RateLimiter {
  if (!rateLimiter) {
    rateLimiter = new RateLimiter(parseInt(env.RATE_LIMIT_PER_MINUTE, 10) || 30);
  }
  return rateLimiter;
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function generateRequestId(): string {
  return crypto.randomUUID();
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ─── AI Classification ────────────────────────────────────────────────────────

async function classifyFindings(
  env: Env,
  file: BatchedFilePayload
): Promise<L2FindingClassification[]> {
  const userPrompt = buildClassificationUserPrompt(file);

  let rawResult: unknown;
  try {
    rawResult = await env.AI.run(AI_MODEL, {
      messages: [
        { role: 'system', content: CLASSIFICATION_SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
    });
  } catch (err) {
    console.error(JSON.stringify({ audit: 'ai_call_failed', error: String(err) }));
    // Return REVIEW for all findings on AI failure
    return file.findings.map((f) => ({
      finding_hash: f.dedup_hash,
      authoritative_cwe_id: f.cwe_id,
      authoritative_cwe_name: f.cwe_category,
      confidence: 0.0,
      blast_radius_lane: 2 as const,
      verdict: 'REVIEW' as const,
      detection_signal: f.detection_signal,
      reasoning: 'AI classification unavailable — routed to human review.',
    }));
  }

  // Extract text from AI response
  let rawText: string;
  if (
    rawResult !== null &&
    typeof rawResult === 'object' &&
    'response' in rawResult &&
    typeof (rawResult as Record<string, unknown>).response === 'string'
  ) {
    rawText = (rawResult as Record<string, unknown>).response as string;
  } else {
    rawText = String(rawResult);
  }

  // Parse JSON array from AI response
  let parsed: unknown;
  try {
    parsed = JSON.parse(extractJsonFromAIResponse(rawText, 'array'));
  } catch {
    console.error(JSON.stringify({ audit: 'ai_json_parse_failed', raw: rawText.slice(0, 200) }));
    return file.findings.map((f) => ({
      finding_hash: f.dedup_hash,
      authoritative_cwe_id: f.cwe_id,
      authoritative_cwe_name: f.cwe_category,
      confidence: 0.0,
      blast_radius_lane: 2 as const,
      verdict: 'REVIEW' as const,
      detection_signal: f.detection_signal,
      reasoning: 'AI returned malformed JSON — routed to human review.',
    }));
  }

  if (!Array.isArray(parsed)) {
    return file.findings.map((f) => ({
      finding_hash: f.dedup_hash,
      authoritative_cwe_id: f.cwe_id,
      authoritative_cwe_name: f.cwe_category,
      confidence: 0.0,
      blast_radius_lane: 2 as const,
      verdict: 'REVIEW' as const,
      detection_signal: f.detection_signal,
      reasoning: 'AI response was not a JSON array — routed to human review.',
    }));
  }

  // Validate each classification
  const classifications: L2FindingClassification[] = [];
  const findingMap = new Map(file.findings.map((f) => [f.dedup_hash, f]));

  for (const item of parsed) {
    const result = l2FindingClassificationSchema.safeParse(item);
    if (!result.success) {
      // Find the corresponding finding and default to REVIEW
      const hashGuess =
        item !== null && typeof item === 'object' && 'finding_hash' in item
          ? String((item as Record<string, unknown>).finding_hash)
          : 'unknown';
      const originalFinding = findingMap.get(hashGuess);
      classifications.push({
        finding_hash: hashGuess,
        authoritative_cwe_id: originalFinding?.cwe_id ?? 'CWE-UNKNOWN',
        authoritative_cwe_name: originalFinding?.cwe_category ?? 'Unknown',
        confidence: 0.0,
        blast_radius_lane: 2,
        verdict: 'REVIEW',
        detection_signal: originalFinding?.detection_signal ?? 'PATTERN_ONLY',
        reasoning: 'AI classification failed schema validation — routed to human review.',
      });
      continue;
    }

    const validated = result.data;
    const originalFinding = findingMap.get(validated.finding_hash);

    classifications.push({
      finding_hash: validated.finding_hash,
      authoritative_cwe_id: validated.authoritative_cwe_id,
      authoritative_cwe_name: validated.authoritative_cwe_name,
      confidence: validated.confidence,
      blast_radius_lane: validated.blast_radius_lane,
      verdict: validated.verdict,
      detection_signal: originalFinding?.detection_signal ?? 'PATTERN_ONLY',
      reasoning: validated.reasoning,
    });
  }

  return classifications;
}

// ─── Heuristic Escalation (Requirement 10) ────────────────────────────────────

async function runHeuristicAnalysis(
  env: Env,
  file: BatchedFilePayload
): Promise<L2EscalationResult> {
  const userPrompt = buildHeuristicUserPrompt(file);

  let rawResult: unknown;
  try {
    rawResult = await env.AI.run(AI_MODEL, {
      messages: [
        { role: 'system', content: HEURISTIC_SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ],
    });
  } catch {
    return {
      file_path: file.file_path,
      heuristic_verdict: 'UNCERTAIN',
      reasoning: 'AI heuristic analysis unavailable.',
      suggested_cwe: null,
    };
  }

  let rawText: string;
  if (
    rawResult !== null &&
    typeof rawResult === 'object' &&
    'response' in rawResult &&
    typeof (rawResult as Record<string, unknown>).response === 'string'
  ) {
    rawText = (rawResult as Record<string, unknown>).response as string;
  } else {
    rawText = String(rawResult);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(extractJsonFromAIResponse(rawText, 'object'));
  } catch {
    return {
      file_path: file.file_path,
      heuristic_verdict: 'UNCERTAIN',
      reasoning: 'AI returned malformed JSON for heuristic analysis.',
      suggested_cwe: null,
    };
  }

  const result = l2EscalationResultSchema.safeParse(parsed);
  if (!result.success) {
    return {
      file_path: file.file_path,
      heuristic_verdict: 'UNCERTAIN',
      reasoning: 'AI heuristic response failed schema validation.',
      suggested_cwe: null,
    };
  }

  return {
    file_path: file.file_path,
    heuristic_verdict: result.data.heuristic_verdict,
    reasoning: result.data.reasoning,
    suggested_cwe: result.data.suggested_cwe,
  };
}

// ─── Triage Handler ───────────────────────────────────────────────────────────

async function handleTriage(
  request: Request,
  env: Env,
  requestId: string
): Promise<Response> {
  const startTime = Date.now();

  // STEP A — Authentication
  const authResult = authenticateRequest(request, env);
  if (!authResult.authenticated) {
    return jsonResponse({ error: authResult.error, request_id: requestId }, 401);
  }

  // STEP B — Method check
  if (request.method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed', request_id: requestId }, 405);
  }

  // STEP C — Parse and validate request body
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body', request_id: requestId }, 400);
  }

  const parseResult = l2BatchPayloadSchema.safeParse(body);
  if (!parseResult.success) {
    return jsonResponse(
      {
        error: 'Request validation failed',
        details: parseResult.error.flatten(),
        request_id: requestId,
      },
      400
    );
  }

  const payload = parseResult.data;

  // STEP D — Rate limiting
  const limiter = getRateLimiter(env);
  if (!limiter.isAllowed(payload.repository)) {
    return new Response(
      JSON.stringify({ error: 'Rate limit exceeded', request_id: requestId }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': '60',
        },
      }
    );
  }

  // STEP E — Size guard
  const maxFindings = parseInt(env.MAX_FINDINGS_PER_REQUEST, 10) || 50;
  const totalFindings = payload.files.reduce((sum, f) => sum + f.findings.length, 0);
  if (totalFindings > maxFindings) {
    return jsonResponse(
      {
        error: `Request contains ${totalFindings} findings, exceeding the limit of ${maxFindings}`,
        request_id: requestId,
      },
      413
    );
  }

  // STEP F — Process findings
  const classifications: L2FindingClassification[] = [];
  const escalationResults: L2EscalationResult[] = [];

  for (const file of payload.files) {
    if (file.is_escalation) {
      const escalationResult = await runHeuristicAnalysis(env, file);
      escalationResults.push(escalationResult);
    } else {
      const fileClassifications = await classifyFindings(env, file);
      classifications.push(...fileClassifications);
    }
  }

  // STEP G — Build response
  const processingTimeMs = Date.now() - startTime;
  const response: L2TriageResponse = {
    request_id: requestId,
    timestamp: new Date().toISOString(),
    pr_ref: payload.pr_ref,
    repository: payload.repository,
    classifications,
    escalation_results: escalationResults,
    processing_time_ms: processingTimeMs,
  };

  // STEP H — Audit log
  const verdictCounts = classifications.reduce(
    (acc, c) => {
      acc[c.verdict.toLowerCase() as 'escalate' | 'dismiss' | 'review']++;
      return acc;
    },
    { escalate: 0, dismiss: 0, review: 0 }
  );

  console.log(
    JSON.stringify({
      audit: 'l2_triage_complete',
      timestamp: new Date().toISOString(),
      request_id: requestId,
      repository: payload.repository,
      pr_ref: payload.pr_ref,
      total_findings: totalFindings,
      total_escalations: escalationResults.length,
      verdicts: verdictCounts,
      processing_time_ms: processingTimeMs,
    })
  );

  return jsonResponse(response, 200);
}

// ─── Health Handler ───────────────────────────────────────────────────────────

function handleHealth(env: Env): Response {
  return jsonResponse(
    {
      status: 'ok',
      timestamp: new Date().toISOString(),
      environment: env.ENVIRONMENT,
    },
    200
  );
}

// ─── Main Fetch Handler ───────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const requestId = generateRequestId();
    const url = new URL(request.url);

    try {
      if (url.pathname === '/health' && request.method === 'GET') {
        return handleHealth(env);
      }

      if (url.pathname === '/triage') {
        return await handleTriage(request, env, requestId);
      }

      return jsonResponse({ error: 'Not found', request_id: requestId }, 404);
    } catch (err) {
      console.error(
        JSON.stringify({
          audit: 'unhandled_error',
          timestamp: new Date().toISOString(),
          request_id: requestId,
          error: err instanceof Error ? err.message : String(err),
        })
      );

      return jsonResponse(
        { error: 'Internal classification error', request_id: requestId },
        500
      );
    }
  },
};
