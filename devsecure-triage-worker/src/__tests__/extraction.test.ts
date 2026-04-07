import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Env } from '../types';

// ─── Re-export the private utility via the worker module for testing ──────────
// extractJsonFromAIResponse is not exported, so we test it indirectly through
// the handler by mocking env.AI to return different raw text formats.

async function importWorker() {
  return (await import('../index')).default;
}

function makeEnv(aiResponse: string): Env {
  return {
    AI: {
      run: vi.fn().mockResolvedValue({ response: aiResponse }),
    } as unknown as Ai,
    DEVSECURE_API_TOKEN: 'test-token-123',
    ENVIRONMENT: 'test',
    MAX_FINDINGS_PER_REQUEST: '50',
    RATE_LIMIT_PER_MINUTE: '100',
  };
}

function makeValidPayload() {
  return {
    pr_ref: 'refs/pull/1/head',
    commit_sha: 'abc123',
    repository: 'test/repo',
    timestamp: new Date().toISOString(),
    scanner_versions: { opengrep: '1.0', bearer: '2.0' },
    summary: {
      total_files_scanned: 1,
      total_raw_findings: 1,
      total_after_dedup: 1,
      total_after_filters: 1,
      total_escalations: 0,
    },
    files: [
      {
        file_path: 'src/api.ts',
        code_context: 'const x = input;',
        is_escalation: false,
        findings: [
          {
            dedup_hash: 'hash-001',
            file_path: 'src/api.ts',
            line_start: 1,
            line_end: 2,
            cwe_id: 'CWE-89',
            cwe_category: 'SQL Injection',
            detection_signal: 'CONVERGED',
            max_severity: 'HIGH',
            max_confidence: 0.9,
            original_findings: [
              { source_scanner: 'opengrep', snippet: 'x = input', rule_id: 'sqli-001' },
            ],
          },
        ],
      },
    ],
  };
}

const validClassification = JSON.stringify([
  {
    finding_hash: 'hash-001',
    authoritative_cwe_id: 'CWE-89',
    authoritative_cwe_name: 'SQL Injection',
    confidence: 0.95,
    blast_radius_lane: 3,
    verdict: 'ESCALATE',
    reasoning: 'Direct SQL injection.',
  },
]);

const mockCtx = {} as ExecutionContext;

function makeRequest(body: unknown): Request {
  return new Request('http://localhost/triage', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer test-token-123',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

describe('AI response JSON extraction', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('Parses clean JSON array without any wrapping', async () => {
    const worker = await importWorker();
    const env = makeEnv(validClassification);
    const res = await worker.fetch(makeRequest(makeValidPayload()), env, mockCtx);
    expect(res.status).toBe(200);
    const json = await res.json() as { classifications: { verdict: string }[] };
    expect(json.classifications[0].verdict).toBe('ESCALATE');
  });

  it('Parses JSON wrapped in ```json ... ``` fence', async () => {
    const worker = await importWorker();
    const fenced = `\`\`\`json\n${validClassification}\n\`\`\``;
    const env = makeEnv(fenced);
    const res = await worker.fetch(makeRequest(makeValidPayload()), env, mockCtx);
    expect(res.status).toBe(200);
    const json = await res.json() as { classifications: { verdict: string }[] };
    expect(json.classifications[0].verdict).toBe('ESCALATE');
  });

  it('Parses JSON wrapped in plain ``` ... ``` fence', async () => {
    const worker = await importWorker();
    const fenced = `\`\`\`\n${validClassification}\n\`\`\``;
    const env = makeEnv(fenced);
    const res = await worker.fetch(makeRequest(makeValidPayload()), env, mockCtx);
    expect(res.status).toBe(200);
    const json = await res.json() as { classifications: { verdict: string }[] };
    expect(json.classifications[0].verdict).toBe('ESCALATE');
  });

  it('Extracts JSON array from response with conversational preamble', async () => {
    const worker = await importWorker();
    const withPreamble = `Sure! Here are the classifications:\n${validClassification}\nLet me know if you need anything else.`;
    const env = makeEnv(withPreamble);
    const res = await worker.fetch(makeRequest(makeValidPayload()), env, mockCtx);
    expect(res.status).toBe(200);
    const json = await res.json() as { classifications: { verdict: string }[] };
    expect(json.classifications[0].verdict).toBe('ESCALATE');
  });

  it('Falls back to REVIEW verdict when AI returns completely unparseable text', async () => {
    const worker = await importWorker();
    const env = makeEnv('Sorry, I cannot classify this finding.');
    const res = await worker.fetch(makeRequest(makeValidPayload()), env, mockCtx);
    expect(res.status).toBe(200);
    const json = await res.json() as { classifications: { verdict: string }[] };
    expect(json.classifications[0].verdict).toBe('REVIEW');
    expect(json.classifications[0].confidence).toBe(0.0);
  });
});
