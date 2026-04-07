// Author: Jeremy Quadri
// src/filters/dispatcher.ts — HTTP dispatcher: fans out per-finding POST requests
// to the L2 Cloudflare Worker /remediate endpoint via Promise.allSettled.

export async function dispatchToL2(payload: any) {
  const baseUrl = process.env.DEVSECURE_WORKER_URL?.replace(/\/$/, '') || '';
  const targetUrl = `${baseUrl}/remediate`;
  const token = process.env.DEVSECURE_API_TOKEN;

  console.log("Dispatching individual findings to L2...");

  const promises = payload.files.flatMap((file: any) =>
    file.findings.map(async (finding: any) => {
      const workerPayload = {
        code_context: {
          snippet: finding.snippet || "/* no snippet */",
          language: "javascript"
        },
        finding: finding
      };

      const response = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(workerPayload)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Worker rejected payload: ${response.status} - ${errorText}`);
      }
      return response.json();
    })
  );

  const results = await Promise.allSettled(promises);
  const failures = results.filter(r => r.status === 'rejected');

  if (failures.length > 0) {
    console.error(`L2 Dispatch had ${failures.length} failures.`);
    throw new Error("One or more L2 dispatches failed.");
  }

  console.log(`Successfully dispatched ${results.length} findings to L2 Worker.`);
}
