import express from "express";
import fetch from "node-fetch";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

const REQ_URL = process.env.REQ_URL;
const RCPT_URL = process.env.RCPT_URL;

if (!REQ_URL || !RCPT_URL) {
  throw new Error("Missing env vars: REQ_URL and RCPT_URL");
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

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

// basic SSRF safety (keeps you from accidentally hitting internal targets)
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

app.post("/fetch/v1.0.0", async (req, res) => {
  const request = req.body;

  // 1) validate request
  if (!validateReq(request)) {
    return res.status(400).json({ error: "request schema invalid", details: validateReq.errors });
  }

  // 2) execute fetch
  const p = request.payload || {};
  const url = p.url;
  const method = p.method || "GET";
  const headers = p.headers || {};
  const timeout_ms = Math.min(Math.max(p.timeout_ms || 10000, 1), 30000);

  if (!url || isBlockedUrl(url)) {
    return res.status(400).json({ error: "blocked or missing url", details: { url } });
  }

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout_ms);

  let resp, text = "";
  try {
    resp = await fetch(url, { method, headers, signal: controller.signal });
    text = await resp.text();
  } catch (e) {
    clearTimeout(t);

    // failure receipt
    const receipt = {
      x402: request.x402,
      trace: {
        request_id: request.trace?.request_id,
        receipt_id: id("rcpt"),
        ts: new Date().toISOString()
      },
      result: { ok: false, status: 0, error: String(e?.message ?? e) }
    };

    if (!validateRcpt(receipt)) {
      return res.status(500).json({ error: "receipt schema invalid (runtime mismatch)", details: validateRcpt.errors });
    }
    return res.status(200).json(receipt);
  } finally {
    clearTimeout(t);
  }

  clearTimeout(t);

  const headersOut = {};
  resp.headers.forEach((v, k) => (headersOut[k] = v));

  // 3) success receipt
  const receipt = {
    x402: request.x402,
    trace: {
      request_id: request.trace?.request_id,
      receipt_id: id("rcpt"),
      ts: new Date().toISOString()
    },
    result: {
      ok: resp.ok,
      status: resp.status,
      headers: headersOut,
      body_preview: text.slice(0, 2000)
    }
  };

  // 4) validate receipt
  if (!validateRcpt(receipt)) {
    return res.status(500).json({ error: "receipt schema invalid (runtime mismatch)", details: validateRcpt.errors });
  }

  return res.status(200).json(receipt);
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`listening on ${port}`));
