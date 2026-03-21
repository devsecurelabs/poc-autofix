// Author: Jeremy Quadri
// env.ts — Shared Env interface for all Worker entry points.

export interface Env {
  AI: Ai;               // Cloudflare Workers AI binding (wrangler.toml [ai])
  VECTOR_INDEX: Vectorize;
  GITHUB_PAT: string;   // wrangler secret put GITHUB_PAT
  HF_API_KEY: string;   // wrangler secret put HF_API_KEY
  SEED_SECRET: string;  // wrangler secret put SEED_SECRET  — protects GET /seed
  JUDGE_API_KEY: string; // wrangler secret put JUDGE_API_KEY — OpenAI key for diversity judge
  RPS_TOKEN: string;     // wrangler secret put RPS_TOKEN — auth for RPS scoring API
  BETTERSTACK_SOURCE_TOKEN?: string; // wrangler secret put BETTERSTACK_SOURCE_TOKEN — Better Stack Logs ingestion
  // Optional overrides — set in wrangler.toml [vars] or via environment; fallbacks used if absent
  CLASSIFIER_MODEL?: string;
  REMEDIATION_MODEL?: string;
  JUDGE_MODEL?: string;  // defaults to "gpt-4o-mini"
  RPS_API_URL?: string;  // RPS scoring endpoint base URL
}
