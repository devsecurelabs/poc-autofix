import { describe, it, expect } from 'vitest';
import { l2BatchPayloadSchema } from '../types';

function makeValidPayload() {
  return {
    pr_ref: 'refs/pull/42/head',
    commit_sha: 'abc123def456',
    repository: 'acme/web-api',
    timestamp: new Date().toISOString(),
    scanner_versions: { opengrep: '1.0.0', bearer: '2.0.0' },
    summary: {
      total_files_scanned: 10,
      total_raw_findings: 5,
      total_after_dedup: 4,
      total_after_filters: 3,
      total_escalations: 1,
    },
    files: [
      {
        file_path: 'src/api.ts',
        code_context: 'const x = req.body.input;',
        is_escalation: false,
        findings: [
          {
            dedup_hash: 'hash-001',
            file_path: 'src/api.ts',
            line_start: 10,
            line_end: 12,
            cwe_id: 'CWE-89',
            cwe_category: 'SQL Injection',
            detection_signal: 'CONVERGED',
            max_severity: 'HIGH',
            max_confidence: 0.9,
            original_findings: [
              { source_scanner: 'opengrep', snippet: 'db.query(input)', rule_id: 'sqli-001' },
            ],
          },
        ],
      },
    ],
  };
}

describe('l2BatchPayloadSchema validation', () => {
  it('Valid L2BatchPayload passes validation', () => {
    const result = l2BatchPayloadSchema.safeParse(makeValidPayload());
    expect(result.success).toBe(true);
  });

  it('Payload with empty files array fails validation', () => {
    const payload = { ...makeValidPayload(), files: [] };
    const result = l2BatchPayloadSchema.safeParse(payload);
    expect(result.success).toBe(false);
  });

  it('Payload with invalid timestamp fails validation', () => {
    const payload = { ...makeValidPayload(), timestamp: 'not-a-date' };
    const result = l2BatchPayloadSchema.safeParse(payload);
    expect(result.success).toBe(false);
  });

  it('Payload exceeding MAX_FINDINGS_PER_REQUEST is a runtime check (schema does not enforce it)', () => {
    // The schema validates structure; the size guard is in the handler
    // This test verifies the schema itself allows many findings
    const payload = makeValidPayload();
    payload.files[0].findings = Array.from({ length: 60 }, (_, i) => ({
      ...payload.files[0].findings[0],
      dedup_hash: `hash-${i}`,
    }));
    const result = l2BatchPayloadSchema.safeParse(payload);
    expect(result.success).toBe(true); // Schema passes; handler enforces the limit
  });
});
