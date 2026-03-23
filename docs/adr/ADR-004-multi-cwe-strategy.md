# ADR-004: Multi-CWE Remediation Strategy

## Status
Decided (v4.0 PoC)

## Context
A single file can contain multiple vulnerabilities. The pipeline currently processes one CWE per
invocation, which can produce conflicting PRs for the same file.

## Options

### A: Sequential Cumulative Patching
Fix CWE-89 → apply patch → fix CWE-79 on patched version. Each fix gets its own gate cycle.

- **Pro:** Smaller blast radius per fix; each gate cycle is independent
- **Con:** Second pass operates on AI-modified code; prohibited by Cloudflare Worker synchronous
  execution timeout constraints; risks compounding hallucinations across passes

### B: Single-Pass Multi-CWE Generation
All detected CWEs sent to the Patch Author agent in one prompt. Single unified patch returned.

- **Pro:** Maintains synchronous execution; single gate cycle; one PR per file
- **Con:** Larger blast radius; higher Patch Guard trigger rate on small files; correlated error
  risk if the model conflates two CWE fixes

## Decision
**Option B — Single-Pass Multi-CWE**

Cloudflare Worker synchronous execution constraints prohibit sequential loops. The multi-CWE
aggregation is L2-anchored: the primary CWE is always the LLM-classified CWE; secondary CWEs
are enrichment signals from `ds_detection.cwe_hint`, capped at 3 total to maintain prompt
stability and gate throughput.

## Consequences

- Patch Guard percentage thresholds may trigger more frequently on multi-CWE patches; the
  small-file absolute mode (< 50 lines → 15-line limit) partially mitigates this.
- The Diversity Judge prompt now enumerates all targeted CWEs and requires
  `all_vulnerabilities_removed: true` in its checklist — a stricter gate than the
  single-CWE `removed_original_vulnerability` check.
- Telemetry logs `uniqueCWEs` at the start of each remediation pass for per-CWE
  success/failure attribution in Better Stack.
- If a multi-CWE patch is blocked, the ghost patch is surfaced in the L4 Issue under a
  collapsed `<details>` block for human reference without auto-application.
