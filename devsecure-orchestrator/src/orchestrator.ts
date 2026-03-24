// Author: Jeremy Quadri
// src/orchestrator.ts — L1 pipeline orchestrator: SARIF → pre-filter → L2 dispatch.
// Separate from src/index.ts (Cloudflare Worker entry point); runs in GitHub Actions.

import { parseSarifToFindings } from "./parsers/index";
import { runPreFilterPipeline, buildL2BatchPayload, dispatchToL2 } from "./filters/index";
import type { SuppressionEntry, PreFilterStats, L2DispatchResult } from "./types";

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface OrchestratorInput {
  opengrep_sarif: unknown;          // Parsed SARIF JSON from OpenGrep
  bearer_sarif:   unknown;          // Parsed SARIF JSON from Bearer
  changed_files:  string[];         // From git diff --name-only
  suppressions:   SuppressionEntry[]; // Loaded from .devsecure-ignore.yml
  config: {
    worker_url:       string;
    api_token:        string;
    pr_ref:           string;
    commit_sha:       string;
    repository:       string;
    scanner_versions: {
      opengrep: string;
      bearer:   string;
    };
  };
}

export interface OrchestratorResult {
  dispatch_result:       L2DispatchResult;
  pipeline_stats:        PreFilterStats[];
  total_raw_findings:    number;
  total_after_filtering: number;
  total_escalations:     number;
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

export async function runOrchestrator(input: OrchestratorInput): Promise<OrchestratorResult> {
  // STEP A — Parse SARIF inputs from both scanners
  const opengrepFindings = parseSarifToFindings(input.opengrep_sarif, "opengrep");
  const bearerFindings   = parseSarifToFindings(input.bearer_sarif,   "bearer");
  const allFindings      = [...opengrepFindings, ...bearerFindings];
  const totalRaw         = allFindings.length;

  // STEP B — Run the L1.5 pre-filter pipeline
  const pipelineOutput = await runPreFilterPipeline({
    raw_findings:  allFindings,
    changed_files: input.changed_files,
    suppressions:  input.suppressions,
  });

  const totalFiltered   = pipelineOutput.normalized_findings.length;
  const escalationCount = pipelineOutput.escalation_payloads.length;

  // STEP C — Build the validated L2 batch payload
  const payload = buildL2BatchPayload({
    pr_ref:              input.config.pr_ref,
    commit_sha:          input.config.commit_sha,
    repository:          input.config.repository,
    scanner_versions:    input.config.scanner_versions,
    normalized_findings: pipelineOutput.normalized_findings,
    escalation_payloads: pipelineOutput.escalation_payloads,
    pipeline_stats:      pipelineOutput.pipeline_stats,
    total_raw:           totalRaw,
  });

  // STEP D — Log pipeline stats audit entry
  console.log(
    JSON.stringify({
      audit:                "pipeline_complete",
      timestamp:            new Date().toISOString(),
      pr_ref:               input.config.pr_ref,
      total_raw:            totalRaw,
      total_filtered:       totalFiltered,
      total_escalations:    escalationCount,
      reduction_percentage: totalRaw > 0
        ? ((1 - totalFiltered / totalRaw) * 100).toFixed(1)
        : "0.0",
      stats:                pipelineOutput.pipeline_stats,
    }),
  );

  // STEP E — Dispatch to L2 Cloudflare Worker
  const dispatchResult = await dispatchToL2(payload, {
    workerUrl: input.config.worker_url,
    apiToken:  input.config.api_token,
  });

  // STEP F — Return combined result
  return {
    dispatch_result:       dispatchResult,
    pipeline_stats:        pipelineOutput.pipeline_stats,
    total_raw_findings:    totalRaw,
    total_after_filtering: totalFiltered,
    total_escalations:     escalationCount,
  };
}
