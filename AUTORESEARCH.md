# DevSecure Constrained Research Loop

## Goal
Maximise `safe_fix_count` while maintaining ALL safety invariants
at zero violations. The metric is safe_fix_rate, not raw merge count.

## Constraints
- Modify ONLY the TUNABLE values in `src/research_target.ts`
- Do NOT modify values marked `as const` (threshold, severity map)
- Do NOT modify `src/index.ts`, the eval harness, or any workflow files
- All experiments run on branch `autoresearch/<tag>` — NEVER on main

## The Loop
1. git checkout -b autoresearch/<tag> from main
2. Run `npm run eval` to establish baseline
3. Formulate a hypothesis (document it in the commit message)
4. Modify TUNABLE values in `src/research_target.ts`
5. Run `npm run eval`
6. Check results:
   - If safe_fix_count improved AND all safety invariants pass → COMMIT
   - If ANY safety invariant fails → REVERT immediately
   - If safe_fix_count regressed → REVERT
   - If cwe_coverage becomes skewed (one CWE dominates) → REVERT
7. NEVER merge to main. NEVER deploy.
   Results are proposals for human review.
