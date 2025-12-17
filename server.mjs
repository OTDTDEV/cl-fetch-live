console.log("SERVER.MJS BOOTED");

import express from "express";
import fetch from "node-fetch";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import crypto from "node:crypto";
import { ethers } from "ethers";

const app = express();
app.use(express.json({ limit: "2mb" }));

/* -------------------- config -------------------- */

const SERVICE_NAME = process.env.SERVICE_NAME?.trim() || "cl-fetch-live";
const ENS_NAME = process.env.ENS_NAME?.trim() || null;
const ETH_RPC_URL = process.env.ETH_RPC_URL?.trim() || null;

const ENV_REQ_URL = process.env.SCHEMA_REQUEST_URL?.trim() || null;
const ENV_RCPT_URL = process.env.SCHEMA_RECEIPT_URL?.trim() || null;

const REQUEST_PATH = "/fetch/v1.0.0";
const DEFAULT_PORT = 8080;

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
  // Railway-safe: allow multiline PEM stored with literal \n
  return v.replace(/\\n/g, "\n").trim();
}

function canonicalJson(obj) {
  // v1: stable enough for now
  return JSON.stringify(obj);
}

function signEd25519(hashHex) {
  const pem = readPemEnv("RECEIPT_SIGNING_PRIVATE_KEY_PEM");
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM");
  const msg = Buffer.from(hashHex, "hex");
  const sig = crypto.sign(null, msg, pem);
  return sig.toString("base64");
}

function attachReceiptProof(receipt) {
  const clone = structuredClone(receipt);
  if (clone?.metadata?.proof) delete clone.metadata.proof;

  const hash = sha256Hex(canonicalJson(clone));

  receipt.metadata = receipt.metadata || {};
  receipt.metadata.proof = {
    alg: "ed25519-sha256",
    canonical: "json-stringify",
    hash_sha256: hash,
    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || SERVICE_NAME
  };

  try {
    receipt.metadata.proof.signature_b64 = signEd25519(hash);
    const pub = readPemEnv("RECEIPT_SIGNING_PUBLIC_KEY_PEM");
    if (pub) receipt.metadata.proof.public_key_pem = pub;
  } catch (e) {
    receipt.metadata.proof.signature_error = String(e?.message ?? e);
  }

  return receipt;
}

// SSRF guard for demo safety
function blocked(url) {
  try {
    const u = new URL(url);
    const h = u.hostname;

    if (u.protocol !== "http:" && u.protocol !== "https:") return true;

    return (
      h === "localhost" ||
      h.endsWith(".local") ||
      /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\./.test(h)
    );
  } catch {
    return true;
  }
}

/* -------------------- schema state -------------------- */

let schemaState = {
  mode: "booting", // booting | ready | degraded
  ok: false,
  reqUrl: null,
  rcptUrl: null,
  error: null
};

let validateReq = null;
let validateRcpt = null;

/* -------------------- always-on routes -------------------- */

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.get("/debug/env", (_req, res) => {
  // must never 500 — this is your lifeline
  try {
    res.status(200).json({
      ok: true,
      node: process.version,
      cwd: process.cwd(),
      port: Number(process.env.PORT || DEFAULT_PORT),
      service: SERVICE_NAME,
      ens_name: ENS_NAME,
      has_rpc: Boolean(ETH_RPC_URL),
      schema_request_url_env: ENV_REQ_URL,
      schema_receipt_url_env: ENV_RCPT_URL,
      signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || SERVICE_NAME,
      has_priv: Boolean(process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM),
      has_pub: Boolean(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM),
      schema_state: schemaState
    });
  } catch (e) {
    res.status(200).json({ ok: false, error: String(e?.message ?? e) });
  }
});

app.post("/debug/reload-schemas", async (_req, res) => {
  await initSchemas();
  res.status(200).json({ ok: true, schema_state: schemaState });
});

/* -------------------- ENS resolution -------------------- */

async function resolveSchemasFromENS() {
  if (!ETH_RPC_URL || !ENS_NAME) throw new Error("Missing ETH_RPC_URL or ENS_NAME");

  const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
  const resolver = await provider.getResolver(ENS_NAME);
  if (!resolver) throw new Error(`No resolver for ${ENS_NAME}`);

  const reqUrl = await resolver.getText("cl.schema.request");
  const rcptUrl = await resolver.getText("cl.schema.receipt");
  if (!reqUrl || !rcptUrl) throw new Error("ENS missing schema TXT records");

  return { reqUrl, rcptUrl };
}

/* -------------------- schema loading -------------------- */

async function buildValidators(reqUrl, rcptUrl) {
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    loadSchema: async (uri) => (await fetch(uri)).json()
  });
  addFormats(ajv);

  const reqSchema = await (await fetch(reqUrl)).json();
  const rcptSchema = await (await fetch(rcptUrl)).json();

  const vReq = await ajv.compileAsync(reqSchema);
  const vRcpt = await ajv.compileAsync(rcptSchema);

  return { vReq, vRcpt };
}

async function initSchemas() {
  try {
    schemaState = { mode: "booting", ok: false, reqUrl: null, rcptUrl: null, error: null };

    // Priority: env URLs -> ENS TXT
    let reqUrl = ENV_REQ_URL;
    let rcptUrl = ENV_RCPT_URL;

    if (!reqUrl || !rcptUrl) {
      const ens = await resolveSchemasFromENS();
      reqUrl = ens.reqUrl;
      rcptUrl = ens.rcptUrl;
    }

    const { vReq, vRcpt } = await buildValidators(reqUrl, rcptUrl);

    validateReq = vReq;
    validateRcpt = vRcpt;

    schemaState = { mode: "ready", ok: true, reqUrl, rcptUrl, error: null };
    console.log("Schemas READY");
  } catch (e) {
    validateReq = null;
    validateRcpt = null;

    schemaState = {
      mode: "degraded",
      ok: false,
      reqUrl: ENV_REQ_URL,
      rcptUrl: ENV_RCPT_URL,
      error: String(e?.message ?? e)
    };

    console.error("Schemas DEGRADED:", schemaState.error);
  }
}

/* -------------------- runtime route -------------------- */

app.post(REQUEST_PATH, async (req, res) => {
  if (!validateReq || !validateRcpt) {
    return res.status(503).json({
      error: "schemas not ready",
      schema: schemaState
    });
  }

  try {
    const request = req.body;

    if (!validateReq(request)) {
      return res.status(400).json({
        error: "request schema invalid",
        details: validateReq.errors
      });
    }

    const url = request.source;
    if (blocked(url)) {
      return res.status(400).json({ error: "blocked or invalid source" });
    }

    const started_at = new Date().toISOString();
    const trace_id = id("trace");

    const controller = new AbortController();
    const timeout_ms = Number(process.env.FETCH_TIMEOUT_MS || 8000);
    const t = setTimeout(() => controller.abort(), timeout_ms);

    let r, text;
    try {
      r = await fetch(url, { signal: controller.signal });
      text = await r.text();
    } finally {
      clearTimeout(t);
    }

    const headers = {};
    r.headers.forEach((v, k) => (headers[k] = v));

    const receipt = {
      status: "success",
      x402: request.x402,
      trace: { trace_id, started_at, completed_at: new Date().toISOString() },
      result: {
        items: [
          {
            source: url,
            query: request.query ?? null,
            include_metadata: request.include_metadata ?? null,
            ok: r.ok,
            http_status: r.status,
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
    const receipt = {
      status: "error",
      x402: { entry: "x402://fetchagent.eth/fetch/v1.0.0", verb: "fetch", version: "1.0.0" },
      trace: { trace_id: id("trace"), started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
      error: { code: "RUNTIME_ERROR", message: String(e?.message ?? e), retryable: true },
      result: { items: [] }
    };

    attachReceiptProof(receipt);

    if (validateRcpt && !validateRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid (error path)",
        details: validateRcpt.errors
      });
    }

    return res.status(200).json(receipt);
  }
});

/* -------------------- start -------------------- */

const port = Number(process.env.PORT || DEFAULT_PORT);
app.listen(port, "0.0.0.0", () => {
  console.log(`listening on ${port}`);
});

// Non-blocking schema init (server is already reachable)
initSchemas();
