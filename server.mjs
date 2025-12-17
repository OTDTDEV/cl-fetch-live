import express from "express";
import fetch from "node-fetch";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import crypto from "node:crypto";
import { ethers } from "ethers";

const app = express();
app.use(express.json({ limit: "2mb" }));

/* -------------------- helpers -------------------- */

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function readPemEnv(name) {
  const v = process.env[name];
  if (!v) return null;
  // Railway/env UIs sometimes store multiline PEM with literal "\n"
  return v.replace(/\\n/g, "\n").trim();
}

function signEd25519(hashHex) {
  const pem = readPemEnv("RECEIPT_SIGNING_PRIVATE_KEY_PEM");
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM");
  const msg = Buffer.from(hashHex, "hex"); // 32-byte hash
  const sig = crypto.sign(null, msg, pem); // Ed25519 ignores hash alg param
  return sig.toString("base64");
}

function attachReceiptProof(receipt) {
  // Hash the receipt *without* metadata.proof to avoid recursion
  const clone = structuredClone(receipt);
  if (clone.metadata && clone.metadata.proof) delete clone.metadata.proof;

  const hash = sha256Hex(JSON.stringify(clone));

  receipt.metadata = receipt.metadata || {};
  receipt.metadata.proof = {
    alg: "ed25519-sha256",
    canonical: "json-stringify",
    hash_sha256: hash,
    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || "cl-fetch-live"
  };

  // Never let proof generation crash the request
  try {
    receipt.metadata.proof.signature_b64 = signEd25519(hash);

    const pub = readPemEnv("RECEIPT_SIGNING_PUBLIC_KEY_PEM");
    if (pub) receipt.metadata.proof.public_key_pem = pub;
  } catch (e) {
    receipt.metadata.proof.signature_error = String(e?.message ?? e);
  }

  return receipt;
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

// basic SSRF guard (demo-safe)
function blocked(url) {
  try {
    const h = new URL(url).hostname;
    return (
      h === "localhost" ||
      h.endsWith(".local") ||
      /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\./.test(h)
    );
  } catch {
    return true;
  }
}

/* -------------------- ENS resolution -------------------- */

async function resolveSchemasFromENS() {
  const rpc = process.env.ETH_RPC_URL?.trim();
  const ensName = process.env.ENS_NAME?.trim();
  if (!rpc || !ensName) throw new Error("Missing ETH_RPC_URL or ENS_NAME");

  const provider = new ethers.JsonRpcProvider(rpc);
  const resolver = await provider.getResolver(ensName);
  if (!resolver) throw new Error(`No ENS resolver for ${ensName}`);

  const reqUrl = await resolver.getText("cl.schema.request");
  const rcptUrl = await resolver.getText("cl.schema.receipt");

  if (!reqUrl || !rcptUrl) {
    throw new Error(`Missing cl.schema.request / cl.schema.receipt on ${ensName}`);
  }

  console.log("ENS resolved schemas:", { reqUrl, rcptUrl });
  return { reqUrl, rcptUrl };
}

/* -------------------- schema loading -------------------- */

const ensResolved = await resolveSchemasFromENS();
const REQ_URL = ensResolved.reqUrl;
const RCPT_URL = ensResolved.rcptUrl;

const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  loadSchema: async (uri) => fetchJson(uri)
});
addFormats(ajv);

const reqSchema = await fetchJson(REQ_URL);
const rcptSchema = await fetchJson(RCPT_URL);
const validateReq = await ajv.compileAsync(reqSchema);
const validateRcpt = await ajv.compileAsync(rcptSchema);

/* -------------------- routes -------------------- */

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.post("/fetch/v1.0.0", async (req, res) => {
  try {
    const request = req.body;

    // validate request
    if (!validateReq(request)) {
      return res.status(400).json({
        error: "request schema invalid",
        details: validateReq.errors
      });
    }

    const url = request.source;
    if (!url || blocked(url)) {
      return res.status(400).json({ error: "blocked or invalid source" });
    }

    const startedAt = new Date().toISOString();
    const traceId = id("trace");

    // outbound fetch with hard timeout so we never hang
    const controller = new AbortController();
    const timeoutMs = 8000;
    const t = setTimeout(() => controller.abort(), timeoutMs);

    let response, text;
    try {
      response = await fetch(url, { signal: controller.signal });
      text = await response.text();
    } finally {
      clearTimeout(t);
    }

    const headers = {};
    response.headers.forEach((v, k) => (headers[k] = v));

    const receipt = {
      status: "success",
      x402: request.x402,
      trace: {
        trace_id: traceId,
        started_at: startedAt,
        completed_at: new Date().toISOString()
      },
      result: {
        items: [
          {
            source: url,
            query: request.query ?? null,
            include_metadata: request.include_metadata ?? null,
            ok: response.ok,
            http_status: response.status,
            headers,
            body_preview: (text || "").slice(0, 2000)
          }
        ]
      }
    };

    attachReceiptProof(receipt);

    if (!validateRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid",
        details: validateRcpt.errors
      });
    }

    return res.json(receipt);
  } catch (e) {
    // Guaranteed response path (no 502 timeouts)
    const receipt = {
      status: "error",
      x402: {
        entry: "x402://fetchagent.eth/fetch/v1.0.0",
        verb: "fetch",
        version: "1.0.0"
      },
      trace: { trace_id: id("trace"), started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
      error: {
        code: "RUNTIME_ERROR",
        message: String(e?.message ?? e),
        retryable: true
      },
      result: { items: [] }
    };

    attachReceiptProof(receipt);

    // If this fails, return raw error (should be rare)
    if (!validateRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid (error path)",
        details: validateRcpt.errors
      });
    }

    return res.status(200).json(receipt);
  }
});

/* -------------------- start -------------------- */

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`listening on ${port}`));
