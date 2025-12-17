import express from "express";
import fetch from "node-fetch";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "2mb" }));

// ---------- required env ----------
const REQ_URL = process.env.REQ_URL?.trim();
const RCPT_URL = process.env.RCPT_URL?.trim();
if (!REQ_URL || !RCPT_URL) throw new Error("Missing env vars: REQ_URL and RCPT_URL");

// ---------- helpers ----------
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

// Basic SSRF safety: block obvious internal targets
function isBlockedUrl(raw) {
  try {
    const u = new URL(raw);
    const h = u.hostname.toLowerCase();
    if (h === "localhost" || h.endsWith(".local")) return true;
    if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(h)) return true;
    return false;
  } catch {
    return true;
  }
}

// ---------- AJV + schema load ----------
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

// ---------- routes ----------
app.get("/health", (_req, res) => res.status(200).send("ok"));

// Keep your old simple endpoint (optional). Safe to delete if you want.
app.post("/fetch/v1", async (req, res) => {
  const url = req.body?.url;
  if (!url) return res.status(400).json({ error: "missing url" });
  if (isBlockedUrl(url)) return res.status(400).json({ error: "blocked url", details: { url } });

  const r = await fetch(url);
  const text = await r.text();

  return res.json({
    request: { url },
    result: { ok: r.ok, status: r.status, body_preview: text.slice(0, 300) },
  });
});

// CommandLayer-style endpoint for fetch v1.0.0 (schema-driven)
app.post("/fetch/v1.0.0", async (req, res) => {
  const request = req.body;

  // 1) Validate request against fetch.request schema
  if (!validateReq(request)) {
    return res.status(400).json({ error: "request schema invalid", details: validateReq.errors });
  }

  // 2) Interpret fetch.request fields
  // Your schema: source is a string. For this live demo, we treat source as a URL to GET.
  const url = request.source;
  if (!url || isBlockedUrl(url)) {
    return res.status(400).json({ error: "blocked or missing source", details: { source: url } });
  }

  const maxItems = Math.min(Math.max(request.max_items ?? 1, 1), 100); // keep demo sane

  // 3) Execute
  let resp, text = "";
  try {
    resp = await fetch(url, { method: "GET" });
    text = await resp.text();
  } catch (e) {
    // ERROR receipt (matches receipt.base requirements you saw)
    const receipt = {
      status: "error",
      x402: request.x402,
      trace: { trace_id: id("trace") },
      result: {
        items: [
          {
            source: url,
            ok: false,
            error: String(e?.message ?? e),
          },
        ],
      },
    };

    if (!validateRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid (runtime mismatch)",
        details: validateRcpt.errors,
      });
    }
    return res.status(200).json(receipt);
  }

  const headersOut = {};
  resp.headers.forEach((v, k) => (headersOut[k] = v));

  // 4) SUCCESS receipt (matches fetch.receipt + your receipt.base constraints discovered so far)
  const receipt = {
    status: "success",
    x402: request.x402,
    trace: { trace_id: id("trace") },
    result: {
      items: [
        {
          source: url,
          query: request.query ?? null,
          include_metadata: request.include_metadata ?? null,
          ok: resp.ok,
          http_status: resp.status,
          headers: headersOut,
          body_preview: text.slice(0, 2000),
        },
      ].slice(0, maxItems),
    },
  };

  // 5) Validate receipt against fetch.receipt schema
  if (!validateRcpt(receipt)) {
    return res.status(500).json({
      error: "receipt schema invalid (runtime mismatch)",
      details: validateRcpt.errors,
    });
  }

  return res.status(200).json(receipt);
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`listening on ${port}`));
