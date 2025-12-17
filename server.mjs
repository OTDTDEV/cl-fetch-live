// inside app.post("/fetch/v1.0.0", ...)

const url = request.source;              // <-- schema says source is a string
const maxItems = request.max_items ?? 1; // <-- optional

// fetch source as URL (GET)
const resp = await fetch(url, { method: "GET" });
const text = await resp.text();

const headersOut = {};
resp.headers.forEach((v, k) => (headersOut[k] = v));

// Put the fetched content into result.items[] (required by fetch.receipt)
const receipt = {
  x402: request.x402,  // must include verb/version
  trace: {
    request_id: request.metadata?.request_id ?? request.metadata?.requestId ?? "req_manual",
    receipt_id: id("rcpt"),
    ts: new Date().toISOString()
  },
  result: {
    items: [
      {
        source: url,
        ok: resp.ok,
        status: resp.status,
        headers: headersOut,
        body_preview: text.slice(0, 2000),
        query: request.query ?? null
      }
    ].slice(0, maxItems)
  }
};
