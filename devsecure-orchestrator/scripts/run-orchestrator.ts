// Author: Jeremy Quadri
// scripts/run-orchestrator.ts — GitHub Actions entry point for the DevSecure L1 detection pipeline.
// Reads SARIF artifacts from both scanners, runs the L1.5 pre-filter pipeline,
// and dispatches the filtered batch to the L2 Cloudflare Worker.

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { load as loadYaml } from "js-yaml";
import { runOrchestrator } from "../src/orchestrator";
import type { SuppressionEntry } from "../src/types";

// ---------------------------------------------------------------------------
// main — invoked by GitHub Actions via: npx tsx scripts/run-orchestrator.ts
// ---------------------------------------------------------------------------

export async function main(): Promise<void> {
  const opengrepSarifPath = process.env.OPENGREP_SARIF  ?? "";
  const bearerSarifPath   = process.env.BEARER_SARIF    ?? "";
  const changedFilesPath  = process.env.CHANGED_FILES   ?? "";
  const suppressionsFile  = process.env.SUPPRESSIONS_FILE ?? "";

  // Read and parse SARIF output from both scanners
  const opengrepSarif = JSON.parse(readFileSync(opengrepSarifPath, "utf-8")) as unknown;
  const bearerSarif   = JSON.parse(readFileSync(bearerSarifPath,   "utf-8")) as unknown;

  // Parse changed files list (one file path per line, blank lines ignored)
  const changedFilesText = readFileSync(changedFilesPath, "utf-8");
  const changedFiles = changedFilesText
    .split("\n")
    .map((f) => f.trim())
    .filter((f) => f.length > 0);

  // Load suppression entries from .devsecure-ignore.yml if the path is set
  let suppressions: SuppressionEntry[] = [];
  if (suppressionsFile) {
    const rawYaml = readFileSync(suppressionsFile, "utf-8");
    suppressions  = loadYaml(rawYaml) as SuppressionEntry[];
  }

  const result = await runOrchestrator({
    opengrep_sarif: opengrepSarif,
    bearer_sarif:   bearerSarif,
    changed_files:  changedFiles,
    suppressions,
    config: {
      worker_url: process.env.DEVSECURE_WORKER_URL ?? "",
      api_token:  process.env.DEVSECURE_API_TOKEN  ?? "",
      pr_ref:     process.env.PR_REF               ?? "",
      commit_sha: process.env.COMMIT_SHA           ?? "",
      repository: process.env.REPOSITORY           ?? "",
      scanner_versions: {
        opengrep: process.env.OPENGREP_VERSION ?? "unknown",
        bearer:   process.env.BEARER_VERSION   ?? "unknown",
      },
    },
  });

  // Fail the GitHub Actions step on dispatch failure (fail-closed guarantee)
  if (!result.dispatch_result.success) {
    console.error(
      "DevSecure: L2 dispatch failed:",
      result.dispatch_result.error_message,
    );
    process.exit(1);
  }

  console.log(
    JSON.stringify({
      summary:           "DevSecure pipeline complete",
      total_raw:         result.total_raw_findings,
      total_filtered:    result.total_after_filtering,
      total_escalations: result.total_escalations,
      dispatch_status:   result.dispatch_result.status,
      request_id:        result.dispatch_result.request_id,
    }),
  );
}

// Guard: only auto-run when this file is the direct entry point (not during tests)
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err: unknown) => {
    console.error("DevSecure: Unhandled error:", err);
    process.exit(1);
  });
}
