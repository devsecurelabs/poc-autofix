// Author: Jeremy Quadri
// embed.ts — Embedding helper using Cloudflare Workers AI (@cf/baai/bge-base-en-v1.5, 768 dims).
// Replaces the Hugging Face embedding call to eliminate external 404 routing issues.

import type { Env } from "./env";

export async function getEmbedding(text: string, env: Env): Promise<number[]> {
  const result = await env.AI.run("@cf/baai/bge-base-en-v1.5", { text: [text] });
  return result.data[0];
}
