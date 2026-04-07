import { describe, it, expect } from 'vitest';
import { l2FindingClassificationSchema } from '../types';

function makeValidClassification() {
  return {
    finding_hash: 'hash-001',
    authoritative_cwe_id: 'CWE-89',
    authoritative_cwe_name: 'SQL Injection',
    confidence: 0.92,
    blast_radius_lane: 3,
    verdict: 'ESCALATE',
    reasoning: 'Direct SQL injection via unsanitised user input in public API.',
  };
}

describe('l2FindingClassificationSchema validation', () => {
  it('Valid classification passes schema validation', () => {
    const result = l2FindingClassificationSchema.safeParse(makeValidClassification());
    expect(result.success).toBe(true);
  });

  it('Classification with confidence > 1.0 fails validation', () => {
    const item = { ...makeValidClassification(), confidence: 1.5 };
    const result = l2FindingClassificationSchema.safeParse(item);
    expect(result.success).toBe(false);
  });

  it('Classification with invalid verdict fails validation', () => {
    const item = { ...makeValidClassification(), verdict: 'APPROVE' };
    const result = l2FindingClassificationSchema.safeParse(item);
    expect(result.success).toBe(false);
  });

  it('Classification with blast_radius_lane 5 fails validation', () => {
    const item = { ...makeValidClassification(), blast_radius_lane: 5 };
    const result = l2FindingClassificationSchema.safeParse(item);
    expect(result.success).toBe(false);
  });
});
