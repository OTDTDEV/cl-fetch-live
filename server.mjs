import express from "express";
import fetch from "node-fetch";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "2mb" }));

const REQ_URL = process.env.REQ_URL;
const RCPT_URL = process.env.RCPT_URL;
if (!REQ_URL || !RCPT_URL) throw new Error("Missing env vars: REQ_URL and RCPT_URL");

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

const cache = new Map();
async function fetchJson(url) {
  if (cache.has(url)) return cache.get(url);
  const r = await fetch(url, { headers: { accept: "application/json" } });
  if (!r.ok) throw new Error(`HTTP ${r.status} fetching ${url}`);
  const j = await r.json();
  cache.set(url, j);
  return j;
}

// AJV + schemas
const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  loadSchema: async (uri) => fetchJson(uri),
});
addFormats(ajv);

const reqSchema = await fetchJson(REQ_URL);
const rcptSchema = await fetchJson(RCPT_URL);
const validateReq = await ajv.compileAsync(reqSchema);
const validateRcpt = await ajv.compileAsync(rcptSchema);

app.get("/health", (_req, res) => res.status(200).send("ok"));

// Keep your old endpoint if you still want it:
app.post("/fetch/v1", async (req, res) => {
  const url = req.body?.url;
  if (!url) return res.status(400).json({ error: "missing url" });
  const r = await fetch(url);
  const text = await r.text();
  return res.json({
    request: { url },
    result: { ok: r.ok, status: r.status, body_preview: text.slice(0, 300) }
  });
});

// CommandLayer-style endpoint for fetch v1.0.0 (schema-driven)
app.post("/fetch/v1.0.0", async (req, res) => {
  console.log("FETCH v1.0.0 BODY:", JSON.stringify(req.body).slice(0, 500));

  const request = req.body;

  // 1) validate request (matches your fetch.request schema)
  if (!validateReq(request)) {
    return res.status(400).json({ error: "request schema invalid", details: validateReq.errors });
  }

  // 2) interpret schema fields
  // Your schema: source = string (we treat it as URL for this demo)
  const url = request.source;

  // 3) execute (simple GET)
  let resp, text = "";
  try {
    resp = await fetch(url, { method: "GET" });
    text = await resp.text();
  } catch (e) {
    // Build a receipt that at least matches fetch.receipt's "result.items"
    const receipt = {
      x402: request.x402,
      trace: { receipt_id: id("rcpt"), ts: new Date().toISOString() },
      result: { items: [{ source: url, ok: false, error: String(e?.message ?? e) }] }
    };

    if (!validateRcpt(receipt)) {
      return res.status(500).json({ error: "receipt schema invalid (runtime mismatch)", details: validateRcpt.errors });
    }
    return res.status(200).json(receipt);
  }

  const headersOut = {};
  resp.headers.forEach((v, k) => (headersOut[k] = v));

  // 4) build receipt to match fetch.receipt (result.items required)
  const receipt = {
    x402: request.x402,
    trace: { receipt_id: id("rcpt"), ts: new Date().toISOString() },
    result: {
      items: [
        {
          source: url,
          query: request.query ?? null,
          ok: resp.ok,
          status: resp.status,
          headers: headersOut,
          body_preview: text.slice(0, 2000)
        }
      ]
    }
  };

  // 5) validate receipt against your fetch.receipt schema
  if (!validateRcpt(receipt)) {
    return res.status(500).json({ error: "receipt schema invalid (runtime mismatch)", details: validateRcpt.errors });
  }

  return res.status(200).json(receipt);
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`listening on ${port}`));
