# L1 Detection Plane Pilot — Expected Results

> ⚠️ **DO NOT MERGE** — This manifest documents deliberate vulnerabilities introduced for pipeline validation only.

| Sample File | CWE | Expected Signal | OpenGrep | Bearer | Severity Gate | Escalation |
|---|---|---|---|---|---|---|
| pilot_sqli_direct.js | CWE-89 | CONVERGED | Catch | Catch | Bypass (critical CWE) | No |
| pilot_sqli_indirect.js | CWE-89 | DATAFLOW_ONLY | Miss | Catch | Bypass (critical CWE) | No |
| pilot_eval_usage.js | CWE-94 | PATTERN_ONLY | Catch | Likely miss | Bypass (critical CWE) | No |
| pilot_auth_clean.js | None | NO_DETECTION_ESCALATION | No findings | No findings | N/A | Yes (auth pattern) |
| pilot_xss_reflected.js | CWE-79 | CONVERGED or PATTERN_ONLY | Catch | Likely catch | Bypass (critical CWE) | No |

## Signal Path Coverage

| Signal Type | Sample | Detection Mechanism |
|---|---|---|
| CONVERGED | pilot_sqli_direct.js | Both OpenGrep (pattern) + Bearer (taint) independently flag the same finding |
| DATAFLOW_ONLY | pilot_sqli_indirect.js | Only Bearer traces taint through the `buildQuery` helper; OpenGrep misses indirection |
| PATTERN_ONLY | pilot_eval_usage.js | Only OpenGrep matches the `eval()` pattern; Bearer lacks a tainted external source |
| NO_DETECTION_ESCALATION | pilot_auth_clean.js | Zero findings + filename matches `HIGH_RISK_FILE_PATTERNS` (`auth`) → Requirement 10 fires |
| CWE bypass validation | pilot_xss_reflected.js | CWE-79 in `CRITICAL_CWE_BYPASS` list — severity gate must not drop even at low confidence |

## Acceptance Criteria

1. The GitHub Action workflow runs to completion without error
2. Pipeline audit logs show `PreFilterStats` for every step (`scope_lock`, `path_filter`, `allowlist`, `severity_gate`, `dedup`)
3. At least one finding produces a `CONVERGED` signal (Sample 1)
4. At least one finding produces a `DATAFLOW_ONLY` signal (Sample 2)
5. At least one finding produces a `PATTERN_ONLY` signal (Sample 3)
6. `pilot_auth_clean.js` triggers a `NO_DETECTION_ESCALATION` payload (Sample 4)
7. No CWE-89 or CWE-79 finding is dropped by the severity gate
8. The L2 dispatch succeeds (HTTP 2xx from the Cloudflare Worker)
9. The `L2BatchPayload` contains all expected files grouped correctly
10. The `pipeline_complete` audit log shows a `reduction_percentage > 0%`
