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

function signEd25519(hashHex) {
  const pem = process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM?.trim();
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM");

  // Sign the raw 32-byte hash
  const msg = Buffer.from(hashHex, "hex");
  const sig = crypto.sign(null, msg, pem);
  return sig.toString("base64");
}

function attachReceiptProof(receipt) {
  // Hash the receipt *without* metadata.proof to avoid recursion
  const clone = structuredClone(receipt);
  if (clone.metadata && clone.metadata.proof) delete clone.metadata.proof;

  const hash = sha256Hex(JSON.stringify(clone));
  const signature = signEd25519(hash);

  receipt.metadata = receipt.metadata || {};
  receipt.metadata.proof = {
    alg: "ed25519-sha256",
    canonical: "json-stringify",
    hash_sha256: hash,
    signature_b64: signature,
    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || "cl-fetch-live",
    public_key_pem: process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM?.trim() || undefined
  };

  // Remove undefined so output is clean
  if (receipt.metadata.proof.public_key_pem === undefined) {
    delete receipt.metadata.proof.public_key_pem;
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

  // execute
  let response, text;
  try {
    response = await fetch(url);
    text = await response.text();
  } catch (e) {
    const receipt = {
      status: "error",
      x402: request.x402,
      trace: {
        trace_id: id("trace"),
        started_at: startedAt,
        completed_at: new Date().toISOString()
      },
      error: {
        code: "FETCH_FAILED",
        message: String(e?.message ?? e),
        retryable: true
      },
      result: { items: [] }
    };

    attachReceiptProof(receipt);

    if (!validateRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid",
        details: validateRcpt.errors
      });
    }

    return res.json(receipt);
  }

  const headers = {};
  response.headers.forEach((v, k) => (headers[k] = v));

  const receipt = {
    status: "success",
    x402: request.x402,
    trace: {
      trace_id: id("trace"),
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
          body_preview: text.slice(0, 2000)
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
});

/* -------------------- start -------------------- */

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`listening on ${port}`));
