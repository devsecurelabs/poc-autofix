// Author: Jeremy Quadri
// src/filters/dispatcher.ts — HTTP dispatcher: maps L2BatchPayload into per-finding
// requests and fans them out to the L2 Cloudflare Worker via Promise.allSettled.

import { l2BatchPayloadSchema } from "../types";
import type { L2BatchPayload, L2DispatchResult, NormalizedFinding } from "../types";

// ---------------------------------------------------------------------------
// Language helper
// ---------------------------------------------------------------------------

const EXT_TO_LANGUAGE: Record<string, string> = {
  '.js':   'javascript',
  '.jsx':  'javascript',
  '.ts':   'typescript',
  '.tsx':  'typescript',
  '.py':   'python',
  '.go':   'go',
  '.java': 'java',
  '.rb':   'ruby',
  '.php':  'php',
  '.cs':   'csharp',
  '.cpp':  'cpp',
  '.c':    'c',
  '.rs':   'rust',
};

function getLanguageFromExtension(filePath: string): string {
  const dot = filePath.lastIndexOf('.');
  const ext  = dot !== -1 ? filePath.slice(dot).toLowerCase() : '';
  return EXT_TO_LANGUAGE[ext] ?? 'plaintext';
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Maps each finding in L2BatchPayload into an individual POST to /remediate,
 * then fans out all requests in parallel via Promise.allSettled.
 * Returns a summary result reflecting how many dispatches succeeded or failed.
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

  const baseUrl   = process.env.DEVSECURE_WORKER_URL?.replace(/\/$/, '') || '';
  const targetUrl = `${baseUrl}/remediate`;

  // --------------------------------------------------------------------------
  // Build one fetch promise per finding
  // --------------------------------------------------------------------------
  const requests = payload.files.flatMap((file) =>
    file.findings.map((finding: NormalizedFinding) => {
      const snippet  = finding.original_findings[0]?.snippet ?? '';
      const language = getLanguageFromExtension(file.file_path);

      const controller = new AbortController();
      setTimeout(() => controller.abort(), timeoutMs);

      return fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${process.env.DEVSECURE_API_TOKEN}`,
        },
        body: JSON.stringify({
          code_context: { snippet, language },
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
        : `HTTP ${result.value.status}`;
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
