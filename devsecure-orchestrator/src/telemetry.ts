// Author: Jeremy Quadri
// telemetry.ts — Better Stack structured event emitter for DevSecure pipeline.
// Secrets are never logged. Fail-closed only where auditCritical=true.

const BETTERSTACK_INGEST_URL = "https://in.logs.betterstack.com/";

export interface TelemetryEvent {
  timestamp: string;                 // ISO 8601 timestamp
  stage: string;                     // pipeline stage name
  run_id: string;                    // X-Trace-Id correlation ID
  cve_id: string | null;             // CVE identifier (dependency vulns only; null for proprietary)
  cwe_id: string | null;             // CWE classification (null for probe events)
  lane: number | null;               // routing lane (1–4; null for probe events)
  confidence: number | null;         // LLM classification confidence (0.0–1.0; null for probe events)
  decision: string;                  // pr_ready | issue_escalated | violation | error
  reason: string;                    // human-readable decision rationale
  final_priority_score?: number | null; // computed priority score (0–100)
  message?: string;                  // optional free-text annotation
}

/**
 * Emit a structured JSON event to Better Stack Logs.
 *
 * @param token         BETTERSTACK_SOURCE_TOKEN from Cloudflare Worker secret
 * @param event         Structured pipeline event payload
 * @param auditCritical If true, throws on missing token or HTTP error (fail-closed).
 *                      Default: false (log locally and continue).
 */
export async function emitEvent(
  token: string | undefined,
  event: TelemetryEvent,
  auditCritical = false,
): Promise<void> {
  // TEMPORARY DEBUG — remove after Better Stack Live Tail delivery is confirmed.
  console.log(JSON.stringify({
    source:        "telemetry_debug",
    action:        "emitEvent_called",
    stage:         event.stage,
    token_present: !!token,
    ingest_url:    BETTERSTACK_INGEST_URL,
  }));

  if (!token) {
    if (auditCritical) {
      throw new Error("telemetry: BETTERSTACK_SOURCE_TOKEN missing — fail-closed for audit-critical event");
    }
    // Non-critical: emit to Worker log and continue without surfacing to caller
    console.log(JSON.stringify({ source: "telemetry_local", ...event }));
    return;
  }

  try {
    const res = await fetch(BETTERSTACK_INGEST_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify(event),
    });

    // TEMPORARY DEBUG — log HTTP response status from Better Stack.
    console.log(JSON.stringify({
      source:  "telemetry_debug",
      action:  "betterstack_response",
      stage:   event.stage,
      status:  res.status,
      ok:      res.ok,
    }));

    if (!res.ok) {
      const status = res.status; // never log token
      if (auditCritical) {
        throw new Error(`telemetry: Better Stack ingest failed — HTTP ${status}`);
      }
      console.error(JSON.stringify({
        source:   "telemetry_error",
        stage:    event.stage,
        status,
        decision: event.decision,
      }));
    }
  } catch (err) {
    if (auditCritical) throw err;
    const msg = err instanceof Error ? err.message : String(err);
    // Redact token from any error string that may have leaked it
    const safe = token ? msg.replaceAll(token, "[REDACTED]") : msg;
    // TEMPORARY DEBUG — log fetch errors as strings.
    console.error(JSON.stringify({ source: "telemetry_debug", action: "fetch_error", stage: event.stage, error: safe }));
  }
}
