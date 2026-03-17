// Author: Jeremy Quadri
// env.ts — Shared Env interface for all Worker entry points.

export interface Env {
  AI: Ai;               // Cloudflare Workers AI binding (wrangler.toml [ai])
  VECTOR_INDEX: Vectorize;
  GITHUB_PAT: string;   // wrangler secret put GITHUB_PAT
  HF_API_KEY: string;   // wrangler secret put HF_API_KEY
  SEED_SECRET: string;  // wrangler secret put SEED_SECRET  — protects GET /seed
}
