import type { Env } from './types';

// ─── Authentication ───────────────────────────────────────────────────────────

export function authenticateRequest(
  request: Request,
  env: Env
): { authenticated: boolean; error?: string } {
  const authHeader = request.headers.get('Authorization');

  if (!authHeader) {
    return { authenticated: false, error: 'Missing Authorization header' };
  }

  if (!authHeader.startsWith('Bearer ')) {
    return { authenticated: false, error: 'Invalid Authorization format. Expected: Bearer <token>' };
  }

  const token = authHeader.slice(7); // Remove "Bearer " prefix
  const expectedToken = env.DEVSECURE_API_TOKEN;

  // Constant-time comparison to prevent timing attacks
  const encoder = new TextEncoder();
  const tokenBytes = encoder.encode(token);
  const expectedBytes = encoder.encode(expectedToken);

  // Pad to same length to avoid length-based timing leaks
  const maxLen = Math.max(tokenBytes.length, expectedBytes.length);
  const paddedToken = new Uint8Array(maxLen);
  const paddedExpected = new Uint8Array(maxLen);
  paddedToken.set(tokenBytes);
  paddedExpected.set(expectedBytes);

  let match: boolean;
  try {
    // timingSafeEqual is available in Cloudflare Workers (non-standard SubtleCrypto extension)
    const subtleCrypto = crypto.subtle as SubtleCrypto & {
      timingSafeEqual?: (a: ArrayBufferView | ArrayBuffer, b: ArrayBufferView | ArrayBuffer) => boolean;
    };
    if (typeof subtleCrypto.timingSafeEqual === 'function') {
      match = subtleCrypto.timingSafeEqual(paddedToken, paddedExpected);
    } else {
      // Fallback: bitwise comparison to avoid early exit, still not perfectly timing-safe
      let diff = 0;
      for (let i = 0; i < maxLen; i++) {
        diff |= paddedToken[i] ^ paddedExpected[i];
      }
      match = diff === 0;
    }
  } catch {
    // If timingSafeEqual throws, treat as mismatch
    match = false;
  }

  // Also verify lengths match (after timing-safe comparison to avoid short-circuit)
  if (!match || tokenBytes.length !== expectedBytes.length) {
    return { authenticated: false, error: 'Invalid API token' };
  }

  return { authenticated: true };
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

export class RateLimiter {
  private readonly maxPerMinute: number;
  private readonly requestLog: Map<string, number[]>;

  constructor(maxPerMinute: number) {
    this.maxPerMinute = maxPerMinute;
    this.requestLog = new Map();
  }

  isAllowed(key: string): boolean {
    const now = Date.now();
    const windowStart = now - 60_000; // 60 seconds ago

    const timestamps = (this.requestLog.get(key) ?? []).filter(
      (ts) => ts > windowStart
    );

    if (timestamps.length >= this.maxPerMinute) {
      // Still update cleaned list to avoid unbounded growth
      this.requestLog.set(key, timestamps);
      return false;
    }

    timestamps.push(now);
    this.requestLog.set(key, timestamps);
    return true;
  }
}
