// Author: Jeremy Quadri
// src/filters/dispatcher.ts — HTTP dispatcher: sends L2BatchPayload to the L2 Cloudflare Worker.

import { l2BatchPayloadSchema } from "../types";
import type { L2BatchPayload, L2DispatchResult } from "../types";

const RETRYABLE_STATUS_CODES  = new Set([429, 502, 503, 504]);
const PERMANENT_FAILURE_CODES = new Set([400, 401, 403, 404]);

/**
 * POSTs a validated L2BatchPayload to the L2 Cloudflare Worker.
 * Retries on transient failures (429, 502, 503, 504) with exponential backoff.
 * Throws synchronously on config/validation errors; never swallows them silently.
 */
export async function dispatchToL2(
  payload: L2BatchPayload,
  config: {
    workerUrl:   string;
    apiToken:    string;
    timeoutMs?:  number;
    maxRetries?: number;
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
  const timeoutMs  = config.timeoutMs  ?? 30_000;
  const maxRetries = config.maxRetries ?? 2;
  const requestId  = crypto.randomUUID();

  const remediateUrl = new URL("/remediate", config.workerUrl).toString();

  const findingsCount    = payload.files.reduce((sum, f) => sum + f.findings.length, 0);
  const escalationsCount = payload.files.filter((f) => f.is_escalation).length;

  // --------------------------------------------------------------------------
  // Retry loop — total attempts = maxRetries + 1
  // --------------------------------------------------------------------------
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      // Exponential backoff: 1000ms * 2^attempt (attempt=1→2000ms, attempt=2→4000ms)
      await new Promise<void>((resolve) => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
    }

    const controller   = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);
    const startTime    = Date.now();

    try {
      const response = await fetch(remediateUrl, {
        method: "POST",
        headers: {
          Authorization:   `Bearer ${config.apiToken}`,
          "Content-Type":  "application/json",
          "X-Request-ID":  requestId,
        },
        body:   JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutHandle);
      const latencyMs         = Date.now() - startTime;
      const responseRequestId = response.headers.get("X-Request-ID") ?? requestId;
      const success           = response.ok;
      const errorMessage      = success ? null : await response.text();

      console.log(
        JSON.stringify({
          audit:              "l2_dispatch",
          timestamp:          new Date().toISOString(),
          attempt:            attempt + 1,
          status:             response.status,
          latency_ms:         latencyMs,
          request_id:         responseRequestId,
          success,
          findings_count:     findingsCount,
          escalations_count:  escalationsCount,
        }),
      );

      const result: L2DispatchResult = {
        success,
        status:        response.status,
        request_id:    responseRequestId,
        latency_ms:    latencyMs,
        error_message: errorMessage,
      };

      // Return immediately on success, permanent failure, or non-retryable status
      if (
        success ||
        PERMANENT_FAILURE_CODES.has(response.status) ||
        !RETRYABLE_STATUS_CODES.has(response.status) ||
        attempt === maxRetries
      ) {
        return result;
      }
      // Otherwise fall through to the next iteration (retry)

    } catch (err) {
      clearTimeout(timeoutHandle);
      const latencyMs  = Date.now() - startTime;
      const isAbort    = err instanceof Error && err.name === "AbortError";
      const errorMessage = isAbort
        ? `Request timed out after ${timeoutMs}ms`
        : err instanceof Error
          ? err.message
          : String(err);

      console.log(
        JSON.stringify({
          audit:             "l2_dispatch",
          timestamp:         new Date().toISOString(),
          attempt:           attempt + 1,
          status:            0,
          latency_ms:        latencyMs,
          request_id:        requestId,
          success:           false,
          findings_count:    findingsCount,
          escalations_count: escalationsCount,
        }),
      );

      const result: L2DispatchResult = {
        success:       false,
        status:        0,
        request_id:    requestId,
        latency_ms:    latencyMs,
        error_message: errorMessage,
      };

      if (attempt === maxRetries) return result;
      // Otherwise fall through to the next iteration (retry on network/timeout errors)
    }
  }

  // Unreachable: the loop always returns on the final attempt, but TypeScript requires this.
  throw new Error("dispatchToL2: unexpected exit from retry loop");
}
