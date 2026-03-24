// Author: Jeremy Quadri
// src/filters/index.ts — Public API for all L1.5 pre-filter functions.

export { normalizePath, filterByScope }                        from "./scope_lock";
export { isExcludedPath, verifyFileContentType, filterByPath } from "./path_filter";
export { shouldDropBySeverity, filterBySeverity }              from "./severity_gate";
export { isSuppressed, filterByAllowlist }                     from "./allowlist";
export {
  computeDedupHash,
  areLikelyDuplicates,
  assignDetectionSignal,
  deduplicateFindings,
} from "./dedup";
export { isHighRiskFile, checkNoDetectionEscalation }          from "./escalation";
export { runPreFilterPipeline, buildL2BatchPayload }           from "./pipeline";
export { dispatchToL2 }                                        from "./dispatcher";
