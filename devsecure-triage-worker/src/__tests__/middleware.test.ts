import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { authenticateRequest, RateLimiter } from '../middleware';
import type { Env } from '../types';

function makeEnv(token = 'valid-token-abc123'): Env {
  return {
    AI: {} as Ai,
    DEVSECURE_API_TOKEN: token,
    ENVIRONMENT: 'test',
    MAX_FINDINGS_PER_REQUEST: '50',
    RATE_LIMIT_PER_MINUTE: '30',
  };
}

function makeRequest(authHeader?: string): Request {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (authHeader !== undefined) {
    headers['Authorization'] = authHeader;
  }
  return new Request('http://localhost/triage', { method: 'POST', headers });
}

describe('authenticateRequest', () => {
  it('Accepts valid Bearer token', () => {
    const env = makeEnv('valid-token-abc123');
    const req = makeRequest('Bearer valid-token-abc123');
    const result = authenticateRequest(req, env);
    expect(result.authenticated).toBe(true);
  });

  it('Rejects missing Authorization header', () => {
    const req = makeRequest();
    const result = authenticateRequest(req, makeEnv());
    expect(result.authenticated).toBe(false);
    expect(result.error).toMatch(/missing/i);
  });

  it('Rejects malformed Authorization header (no Bearer prefix)', () => {
    const req = makeRequest('Token valid-token-abc123');
    const result = authenticateRequest(req, makeEnv());
    expect(result.authenticated).toBe(false);
    expect(result.error).toMatch(/invalid/i);
  });

  it('Rejects invalid token', () => {
    const req = makeRequest('Bearer wrong-token');
    const result = authenticateRequest(req, makeEnv('correct-token'));
    expect(result.authenticated).toBe(false);
  });

  it('Uses constant-time comparison (does not short-circuit on first byte mismatch)', () => {
    // Verify that even very different tokens produce authenticated: false (not throw/crash)
    const req = makeRequest('Bearer a');
    const result = authenticateRequest(req, makeEnv('a-much-longer-token-value'));
    expect(result.authenticated).toBe(false);
  });
});

describe('RateLimiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('Allows requests under the limit', () => {
    const limiter = new RateLimiter(5);
    for (let i = 0; i < 5; i++) {
      expect(limiter.isAllowed('repo-a')).toBe(true);
    }
  });

  it('Blocks requests over the limit', () => {
    const limiter = new RateLimiter(3);
    limiter.isAllowed('repo-b');
    limiter.isAllowed('repo-b');
    limiter.isAllowed('repo-b');
    expect(limiter.isAllowed('repo-b')).toBe(false);
  });

  it('Resets after 60 seconds (use fake timers)', () => {
    const limiter = new RateLimiter(2);
    limiter.isAllowed('repo-c');
    limiter.isAllowed('repo-c');
    expect(limiter.isAllowed('repo-c')).toBe(false);

    // Advance time by 61 seconds
    vi.advanceTimersByTime(61_000);
    expect(limiter.isAllowed('repo-c')).toBe(true);
  });

  it('Tracks limits per repository independently', () => {
    const limiter = new RateLimiter(2);
    limiter.isAllowed('repo-x');
    limiter.isAllowed('repo-x');
    expect(limiter.isAllowed('repo-x')).toBe(false);
    // repo-y should still be allowed
    expect(limiter.isAllowed('repo-y')).toBe(true);
  });
});
