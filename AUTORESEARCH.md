# DevSecure v4.0 — Prompt Autoresearch Protocol

> **Purpose:** A repeatable, fail-closed loop for tuning the L2 and L3 system
> prompts to maximise `safe_fix_count` without ever weakening a safety guarantee.

---

## 1. Objective

**Primary metric:** `safe_fix_count` (number of samples routed to `pr_opened`).
**Secondary metric:** `safe_fix_rate` = `safe_fix_count / total_samples`.
**Hard constraint:** Every safety invariant in the `ResearchReport` must remain at **zero** (or `false`).
A higher `safe_fix_count` that breaks any invariant is not an improvement — it is a regression.

---

## 2. Tunable Surface

**The only file you may modify is `src/prompts_target.ts`.**

| Export | Agent | What it controls |
| :--- | :--- | :--- |
| `CLASSIFY_SYSTEM_PROMPT` | L2 Classifier (Qwen2.5-Coder) | Instructions for identifying the CWE, assigning confidence and lane |
| `buildRemediatePrompt(lang, cwes, constraints)` | L3 Remediation (Qwen3) | Instructions for generating a safe, targeted patch |

Tunable wording includes: role descriptions, output-format instructions, emphasis on specific CWEs, tone (concise vs. verbose), ordering of rules, and examples. Do **not** change the JSON schema shapes or the function signature of `buildRemediatePrompt`.

### Off-limits (IMMUTABLE)

```
src/index.ts                  — pipeline logic, never touch
scripts/eval_harness.ts       — scoring + invariant enforcement, never touch
scripts/prompts_baseline.snapshot  — human baseline, never touch
src/research_target.ts        — scoring constants, never touch
Any GitHub Actions workflow   — never touch
```

The eval harness enforces `prompt_diff_violation` as a hard invariant:
if more than **5 lines** of `src/prompts_target.ts` differ from `scripts/prompts_baseline.snapshot`
in a single iteration, the run fails immediately.

---

## 3. Safety Invariants

All of the following must equal zero (or `false`) after every experiment.
If any is non-zero the run **fails** and all changes must be reverted.

| Field | Meaning | Trigger |
| :--- | :--- | :--- |
| `integrity_failures` | Routing integrity violation | State Integrity Matrix breach |
| `severity_floor_violations` | CWE severity ≥ 85 but `final_score` < 60 | Critical CWE under-scored |
| `bonus_cap_violations` | `verification_bonus` > `lane_weight` | Bonus cap overflow |
| `threshold_tamper_detected` | `AUTO_MERGE_THRESHOLD !== 70` | Immutable constant mutated |
| `regression_detected` | File previously `pr_opened` now `issue_escalated` | Safe-fix regression |
| `classification_mismatch_count` | Detected CWE ≠ corpus manifest ground truth | Classification accuracy failure |
| `confidence_spike_detected` | `avg_confidence_score` > 0.95 | Confidence reward hacking |
| `prompt_diff_violation` | More than 5 lines changed vs baseline snapshot | Prompt mutation limit exceeded |

---

## 4. The Loop

```bash
git checkout main
git pull
git checkout -b autoresearch/<tag>    # e.g. autoresearch/prompt-classify-v1
```

### Step-by-step

1. **Baseline** — run `npm run eval` from `devsecure-orchestrator/`.
   Record `safe_fix_count`, `safe_fix_rate`, `avg_priority_score`, and all invariant fields.

2. **Hypothesis** — write one sentence explaining which prompt you will change,
   in which direction, and why you expect it to increase `safe_fix_count`.
   Example: *"Adding an explicit example of CWE-79 lane-2 in CLASSIFY_SYSTEM_PROMPT
   should raise confidence for XSS files above the 0.85 judge-approval threshold."*

3. **Modify** — edit ONLY `src/prompts_target.ts`. Change at most 5 lines per iteration.
   Verify the line count with: `diff src/prompts_target.ts scripts/prompts_baseline.snapshot | grep -c '^[<>]'`

4. **Verify** — run `npm run eval` again.

5. **Decision** — apply the table below.

6. **Commit or revert** — see §5.

7. **Repeat** — iterate on the same branch.

### Decision table

| Outcome | Action |
| :--- | :--- |
| `safe_fix_count` ↑ AND all invariants = 0 / false | **COMMIT** — document hypothesis + delta in message |
| `safe_fix_count` unchanged AND all invariants = 0 / false | Neutral — revert or keep as stylistic clean-up only |
| Any invariant > 0 (or `true`) | **REVERT immediately** — do not commit |
| `safe_fix_count` ↓ (regression) | **REVERT** |
| `prompt_diff_violation = true` | **REVERT** — you changed more than 5 lines; split into smaller iterations |
| `confidence_spike_detected = true` | **REVERT** — wording is inflating confidence artificially |
| `classification_mismatch_count` > 0 | **REVERT** — prompt is mis-classifying manifest-covered files |

---

## 5. Commit & Revert Protocol

### Committing a passing experiment

```bash
# From devsecure-orchestrator/
git add src/prompts_target.ts
git commit -m "autoresearch: <hypothesis one-liner>

Before: safe_fix_count=N  safe_fix_rate=X  avg_score=Y
After:  safe_fix_count=N' safe_fix_rate=X' avg_score=Y'
Lines changed vs snapshot: K
All safety invariants: 0 / false"
```

### Reverting a failing experiment

```bash
git checkout -- src/prompts_target.ts
# Confirm clean
npm run eval
```

### Branch lifecycle

- Branches named `autoresearch/*` are **never merged to `main`**.
- They are proposals for human review and cherry-pick only.
- Open a PR from `autoresearch/<tag>` → `main` if a human approves the change.
- After the PR is merged or closed, **update `scripts/prompts_baseline.snapshot` manually**
  to match the new `src/prompts_target.ts` before the next autoresearch session.
- Delete the branch after the PR is merged or closed.

---

## 6. What NEVER to do

- **Never** modify `src/index.ts`, `scripts/eval_harness.ts`, or any GitHub Actions workflow.
- **Never** modify `src/research_target.ts` (scoring constants).
- **Never** modify `scripts/prompts_baseline.snapshot` — only a human may update it.
- **Never** push to `main` directly from an autoresearch branch.
- **Never** run `wrangler deploy` during an autoresearch session.
- **Never** disable or skip the eval harness to force a green result.
- **Never** delete `scripts/eval_baseline.json` to reset regression tracking.
- **Never** change more than 5 lines of `src/prompts_target.ts` in a single iteration.
- **Never** change the JSON schema shapes or the `buildRemediatePrompt` function signature.

---

## 7. Example Hypotheses

| Hypothesis | Rationale | Risk |
| :--- | :--- | :--- |
| Add a concrete CWE-79 lane assignment example to `CLASSIFY_SYSTEM_PROMPT` | XSS files currently score lane 3; an example may steer the model to lane 2, raising `severity_base` × `confidence` above threshold | Could raise `classification_mismatch_count` if wrong CWEs get lane 2 |
| Reword "short explanation" → "one sentence explanation of the injection point" in classifier | More specific summary guidance may increase classification confidence for ambiguous files | Verbose outputs could cause JSON parse failures — watch `integrity_failures` |
| Add "prefer lane 1 for single-function fixes" to `buildRemediatePrompt` | Nudges the model to declare trivial fixes, which raises lane 1 routing and improves scores | May cause `severity_floor_violations` if high-severity CWEs are mis-laned |
| Strengthen CWE-79 anti-CWE-20 instruction in `CLASSIFY_SYSTEM_PROMPT` | Reduces mis-classification of XSS as generic input validation | Low risk — improves `classification_mismatch_count` if anything |

---

## 8. Reading the ResearchReport

```jsonc
{
  "total_samples":                41,
  "safe_fix_count":               35,    // ← optimise this
  "safe_fix_rate":                0.854,
  "escalation_count":              6,
  "avg_priority_score":           74.05,
  "integrity_failures":            0,    // MUST be 0
  "regression_detected":           0,    // MUST be 0
  "severity_floor_violations":     0,    // MUST be 0
  "bonus_cap_violations":          0,    // MUST be 0
  "threshold_tamper_detected":  false,   // MUST be false
  "classification_mismatch_count": 0,    // MUST be 0
  "avg_confidence_score":        0.87,   // input for spike check
  "confidence_spike_detected":  false,   // MUST be false (threshold > 0.95)
  "prompt_diff_violation":      false,   // MUST be false (limit: 5 lines)
  "cwe_coverage": {                      // watch for distribution skew
    "CWE-89": 20,
    "CWE-79":  6,
    "CWE-78":  4,
    "CWE-287": 4,
    "CWE-22":  4,
    "CWE-94":  3
  }
}
```
