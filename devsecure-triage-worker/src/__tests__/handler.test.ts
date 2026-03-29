import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Env } from '../types';

// We test the handler by importing the default export
// Note: We mock env.AI since we cannot run real Cloudflare AI in unit tests

async function importWorker() {
  // Dynamic import to allow vitest module mocking
  return (await import('../index')).default;
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    AI: {
      run: vi.fn().mockResolvedValue({ response: '[]' }),
    } as unknown as Ai,
    DEVSECURE_API_TOKEN: 'test-token-123',
    ENVIRONMENT: 'test',
    MAX_FINDINGS_PER_REQUEST: '50',
    RATE_LIMIT_PER_MINUTE: '100',
    ...overrides,
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

function makeRequest(options: {
  method?: string;
  path?: string;
  auth?: string | null;
  body?: unknown;
}): Request {
  const { method = 'POST', path = '/triage', auth = 'Bearer test-token-123', body } = options;
  const headers: Record<string, string> = {};
  if (auth !== null) headers['Authorization'] = auth;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  return new Request(`http://localhost${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

const mockCtx = {} as ExecutionContext;

describe('Worker handler integration', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('Returns 401 for missing auth token', async () => {
    const worker = await importWorker();
    const req = makeRequest({ auth: null });
    const res = await worker.fetch(req, makeEnv(), mockCtx);
    expect(res.status).toBe(401);
  });

  it('Returns 405 for GET request to /triage', async () => {
    const worker = await importWorker();
    const req = makeRequest({ method: 'GET', path: '/triage' });
    const res = await worker.fetch(req, makeEnv(), mockCtx);
    expect(res.status).toBe(405);
  });

  it('Returns 400 for invalid payload', async () => {
    const worker = await importWorker();
    const req = makeRequest({ body: { invalid: 'payload' } });
    const res = await worker.fetch(req, makeEnv(), mockCtx);
    expect(res.status).toBe(400);
  });

  it('Returns 429 when rate limited', async () => {
    const worker = await importWorker();
    const env = makeEnv({ RATE_LIMIT_PER_MINUTE: '1' });
    const payload = makeValidPayload();

    // First request passes
    const req1 = makeRequest({ body: payload });
    await worker.fetch(req1, env, mockCtx);

    // Second request is rate limited
    const req2 = makeRequest({ body: payload });
    const res2 = await worker.fetch(req2, env, mockCtx);
    expect(res2.status).toBe(429);
    expect(res2.headers.get('Retry-After')).toBe('60');
  });

  it('Returns 200 for valid request (mock AI response)', async () => {
    const worker = await importWorker();
    const aiResponse = JSON.stringify([
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

    const env = makeEnv({
      AI: { run: vi.fn().mockResolvedValue({ response: aiResponse }) } as unknown as Ai,
    });

    const req = makeRequest({ body: makeValidPayload() });
    const res = await worker.fetch(req, env, mockCtx);
    expect(res.status).toBe(200);

    const json = await res.json() as { classifications: unknown[] };
    expect(json.classifications).toHaveLength(1);
  });

  it('Returns health check on GET /health', async () => {
    const worker = await importWorker();
    const req = makeRequest({ method: 'GET', path: '/health', auth: null });
    const res = await worker.fetch(req, makeEnv(), mockCtx);
    expect(res.status).toBe(200);
    const json = await res.json() as { status: string };
    expect(json.status).toBe('ok');
  });

  it('Returns 404 for unknown routes', async () => {
    const worker = await importWorker();
    const req = makeRequest({ method: 'GET', path: '/unknown' });
    const res = await worker.fetch(req, makeEnv(), mockCtx);
    expect(res.status).toBe(404);
  });

  it('Logs audit entry on successful triage', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const worker = await importWorker();

    const env = makeEnv({
      AI: {
        run: vi.fn().mockResolvedValue({ response: '[]' }),
      } as unknown as Ai,
    });

    const req = makeRequest({ body: makeValidPayload() });
    await worker.fetch(req, env, mockCtx);

    const auditCall = consoleSpy.mock.calls.find((call) => {
      try {
        const parsed = JSON.parse(call[0] as string);
        return parsed.audit === 'l2_triage_complete';
      } catch {
        return false;
      }
    });

    expect(auditCall).toBeDefined();
    consoleSpy.mockRestore();
  });
});
