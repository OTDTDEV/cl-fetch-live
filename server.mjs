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
const PORT = Number(process.env.PORT || 8080);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);
const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 10 * 60 * 1000);

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
  return v.replace(/\\n/g, "\n").trim();
}

function canonicalJson(obj) {
  return JSON.stringify(obj);
}

function recomputeReceiptHash(receipt) {
  const clone = structuredClone(receipt);
  if (clone?.metadata?.proof) delete clone.metadata.proof;
  return sha256Hex(canonicalJson(clone));
}

function signEd25519(hashHex) {
  const pem = readPemEnv("RECEIPT_SIGNING_PRIVATE_KEY_PEM");
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM");
  const msg = Buffer.from(hashHex, "hex");
  const sig = crypto.sign(null, msg, pem);
  return sig.toString("base64");
}

function attachReceiptProofOrThrow(receipt) {
  const hash = recomputeReceiptHash(receipt);

  receipt.metadata = receipt.metadata || {};
  receipt.metadata.proof = {
    alg: "ed25519-sha256",
    canonical: "json-stringify",
    hash_sha256: hash,
    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || SERVICE_NAME,
    signature_b64: signEd25519(hash),
  };

  // IMPORTANT: do NOT embed public key in receipts
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
      h === "::1" ||
      /^127\./.test(h) ||
      /^10\./.test(h) ||
      /^192\.168\./.test(h) ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(h) ||
      /^169\.254\./.test(h) // link-local
    );
  } catch {
    return true;
  }
}

/* -------------------- ENS resolution -------------------- */

async function getEnsResolver() {
  if (!ETH_RPC_URL || !ENS_NAME) throw new Error("Missing ETH_RPC_URL or ENS_NAME");
  const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
  const resolver = await provider.getResolver(ENS_NAME);
  if (!resolver) throw new Error(`No resolver for ${ENS_NAME}`);
  return resolver;
}

async function resolveSchemasFromENS() {
  const resolver = await getEnsResolver();
  const reqUrl = await resolver.getText("cl.schema.request");
  const rcptUrl = await resolver.getText("cl.schema.receipt");
  if (!reqUrl || !rcptUrl) throw new Error("ENS missing schema TXT records");
  return { reqUrl, rcptUrl };
}

async function resolveVerifierKeyFromENS() {
  const resolver = await getEnsResolver();
  const pub_pem_escaped = await resolver.getText("cl.receipt.pubkey_pem");
  if (!pub_pem_escaped) throw new Error("ENS missing cl.receipt.pubkey_pem");

  const signer_id = (await resolver.getText("cl.receipt.signer_id"))?.trim() || null;
  const alg = (await resolver.getText("cl.receipt.alg"))?.trim() || null;

  return {
    alg,
    signer_id,
    pubkey_pem: pub_pem_escaped.replace(/\\n/g, "\n").trim(),
  };
}

/* -------------------- schema loading (non-blocking) -------------------- */

let schemaState = { mode: "booting", ok: false, reqUrl: null, rcptUrl: null, error: null };
let validateReq = null;
let validateRcpt = null;

async function buildValidators(reqUrl, rcptUrl) {
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    loadSchema: async (uri) => (await fetch(uri)).json(),
  });
  addFormats(ajv);

  const reqSchema = await (await fetch(reqUrl)).json();
  const rcptSchema = await (await fetch(rcptUrl)).json();

  return {
    vReq: await ajv.compileAsync(reqSchema),
    vRcpt: await ajv.compileAsync(rcptSchema),
  };
}

async function initSchemas() {
  try {
    schemaState = { mode: "booting", ok: false, reqUrl: null, rcptUrl: null, error: null };

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
      error: String(e?.message ?? e),
    };
    console.error("Schemas DEGRADED:", schemaState.error);
  }
}

/* -------------------- ENS verifier key cache -------------------- */

let ensKeyCache = null; // { pubkey_pem, alg, signer_id, cached_at, expires_at, error }

async function getEnsVerifierKey({ refresh = false } = {}) {
  const now = Date.now();
  if (!refresh && ensKeyCache?.pubkey_pem && ensKeyCache?.expires_at && now < Date.parse(ensKeyCache.expires_at)) {
    return { ...ensKeyCache, source: "ens-cache" };
  }

  const k = await resolveVerifierKeyFromENS();
  ensKeyCache = {
    ...k,
    cached_at: new Date(now).toISOString(),
    expires_at: new Date(now + ENS_CACHE_TTL_MS).toISOString(),
    error: null,
  };
  return { ...ensKeyCache, source: "ens" };
}

/* -------------------- always-on routes -------------------- */

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.get("/debug/env", async (_req, res) => {
  let signer_ok = false;
  let signer_error = null;

  try {
    // sign a dummy hash to prove key is valid
    const dummy = sha256Hex("debug");
    signEd25519(dummy);
    signer_ok = true;
  } catch (e) {
    signer_error = String(e?.message ?? e);
  }

  res.json({
    ok: true,
    node: process.version,
    cwd: process.cwd(),
    port: PORT,
    service: SERVICE_NAME,
    ens_name: ENS_NAME,
    has_rpc: Boolean(ETH_RPC_URL),
    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || SERVICE_NAME,
    has_priv: Boolean(process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM),
    has_pub: Boolean(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM),
    signer_ok,
    signer_error,
    schema_state: schemaState,
  });
});

/* -------------------- /verify -------------------- */

app.post("/verify", async (req, res) => {
  try {
    const receipt = req.body;

    const proof = receipt?.metadata?.proof || null;
    if (!proof?.signature_b64 || !proof?.hash_sha256) {
      return res.status(400).json({ ok: false, error: "missing metadata.proof.signature_b64 or hash_sha256" });
    }

    // schema validation
    const schema_valid = validateRcpt ? Boolean(validateRcpt(receipt)) : false;
    const schema_errors = validateRcpt ? (validateRcpt.errors || null) : [{ message: "receipt validator not ready", schemaState }];

    // hash recompute
    const recomputed_hash = recomputeReceiptHash(receipt);
    const claimed_hash = String(proof.hash_sha256);
    const hash_matches = recomputed_hash === claimed_hash;

    // key selection
    const requireEns = String(req.query?.ens || "") === "1";
    const refresh = String(req.query?.refresh || "") === "1";

    let pubPem = null;
    let pubkey_source = null;

    if (requireEns) {
      const k = await getEnsVerifierKey({ refresh });
      pubPem = k.pubkey_pem;
      pubkey_source = k.source; // ens or ens-cache
    } else {
      pubPem = readPemEnv("RECEIPT_SIGNING_PUBLIC_KEY_PEM");
      pubkey_source = pubPem ? "env" : null;
    }

    if (!pubPem) {
      return res.status(503).json({ ok: false, error: requireEns ? "ENS verifier key unavailable" : "Missing env verifier key" });
    }

    // signature verify (ed25519 over hash bytes)
    let signature_valid = false;
    let signature_error = null;
    try {
      const msg = Buffer.from(recomputed_hash, "hex");
      const sig = Buffer.from(proof.signature_b64, "base64");
      signature_valid = crypto.verify(null, msg, pubPem, sig);
    } catch (e) {
      signature_error = String(e?.message ?? e);
      signature_valid = false;
    }

    return res.json({
      ok: true,
      checks: { schema_valid, hash_matches, signature_valid },
      values: {
        signer_id: proof.signer_id || null,
        alg: proof.alg || null,
        canonical: proof.canonical || null,
        claimed_hash,
        recomputed_hash,
        pubkey_source,
      },
      errors: { schema_errors, signature_error },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message ?? e) });
  }
});

/* -------------------- runtime route -------------------- */

app.post(REQUEST_PATH, async (req, res) => {
  if (!validateReq || !validateRcpt) {
    return res.status(503).json({ error: "schemas not ready", schema: schemaState });
  }

  try {
    const request = req.body;

    if (!validateReq(request)) {
      return res.status(400).json({ error: "request schema invalid", details: validateReq.errors });
    }

    const url = request.source;
    if (blocked(url)) {
      return res.status(400).json({ error: "blocked or invalid source" });
    }

    const started_at = new Date().toISOString();
    const trace_id = id("trace");

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

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
      trace: { trace_id, started_at, completed_at: new Date().toISOString(), provider: SERVICE_NAME },
      result: {
        items: [
          {
            source: url,
            query: request.query ?? null,
            include_metadata: request.include_metadata ?? null,
            ok: r.ok,
            http_status: r.status,
            headers,
            body_preview: (text || "").slice(0, 2000),
          },
        ],
      },
    };

    // If signing fails, fail loudly. No silent unsigned receipts.
    attachReceiptProofOrThrow(receipt);

    if (!validateRcpt(receipt)) {
      return res.status(500).json({ error: "receipt schema invalid", details: validateRcpt.errors });
    }

    return res.json(receipt);
  } catch (e) {
    // If we error before we can sign, return a clear runtime error (not a fake receipt).
    return res.status(500).json({ error: "runtime_error", message: String(e?.message ?? e) });
  }
});

/* -------------------- start -------------------- */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`listening on ${PORT}`);
});

initSchemas();
