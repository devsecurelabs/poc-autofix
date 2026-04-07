// Author: Jeremy Quadri
// src/filters/dispatcher.ts — HTTP dispatcher: fans out per-finding POST requests
// to the L2 Cloudflare Worker /remediate endpoint via Promise.allSettled.

import { l2BatchPayloadSchema } from "../types";
import type { L2BatchPayload, L2DispatchResult } from "../types";

/**
 * Iterates every finding in the L2BatchPayload and POSTs each one individually
 * to the /remediate endpoint. All requests are fired concurrently via
 * Promise.allSettled so a single failure does not cancel the rest.
 */
export async function dispatchToL2(
  payload: L2BatchPayload,
  config: {
    workerUrl:  string;
    apiToken:   string;
    timeoutMs?: number;
  },
): Promise<L2DispatchResult> {
  // --------------------------------------------------------------------------
  // Validation (fail-fast, before any network I/O)
  // --------------------------------------------------------------------------
  if (!config.apiToken || config.apiToken.trim() === "") {
    throw new Error("L2 dispatch aborted: API token is empty");
  }
  if (!config.workerUrl || !config.workerUrl.startsWith("https://")) {
    throw new Error("L2 dispatch aborted: invalid Worker URL");
  }

  const schemaResult = l2BatchPayloadSchema.safeParse(payload);
  if (!schemaResult.success) {
    throw new Error(schemaResult.error.message);
  }

  // --------------------------------------------------------------------------
  // Setup
  // --------------------------------------------------------------------------
  const timeoutMs = config.timeoutMs ?? 30_000;
  const requestId = crypto.randomUUID();
  const startTime = Date.now();

  const targetUrl = `${process.env.DEVSECURE_WORKER_URL?.replace(/\/$/, '')}/remediate`;

  // --------------------------------------------------------------------------
  // Build one fetch promise per finding
  // --------------------------------------------------------------------------
  const requests = payload.files.flatMap((file) =>
    file.findings.map((finding) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const snippet = (finding as any).snippet || "/* no snippet */";

      const controller = new AbortController();
      setTimeout(() => controller.abort(), timeoutMs);

      return fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${process.env.DEVSECURE_API_TOKEN}`,
        },
        body: JSON.stringify({
          code_context: {
            snippet,
            language: "javascript",
          },
          finding,
        }),
        signal: controller.signal,
      });
    }),
  );

  // --------------------------------------------------------------------------
  // Fan out — collect all outcomes without short-circuiting
  // --------------------------------------------------------------------------
  const settled   = await Promise.allSettled(requests);
  const latencyMs = Date.now() - startTime;

  let succeeded = 0;
  let failed    = 0;
  const errors: string[] = [];

  for (const result of settled) {
    if (result.status === 'fulfilled' && result.value.ok) {
      succeeded++;
    } else {
      failed++;
      const msg = result.status === 'rejected'
        ? String(result.reason)
        : `HTTP ${(result as PromiseFulfilledResult<Response>).value.status}`;
      errors.push(msg);
    }
  }

  const success = failed === 0 && settled.length > 0;

  console.log(
    JSON.stringify({
      audit:            "l2_dispatch",
      timestamp:        new Date().toISOString(),
      request_id:       requestId,
      total_dispatched: settled.length,
      succeeded,
      failed,
      latency_ms:       latencyMs,
    }),
  );

  return {
    success,
    status:        success ? 200 : 207,
    request_id:    requestId,
    latency_ms:    latencyMs,
    error_message: errors.length > 0 ? errors.join('; ') : null,
  };
}
