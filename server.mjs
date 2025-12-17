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
  return v.replace(/\\n/g, "\n").trim();
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
  if (clone.metadata?.proof) delete clone.metadata.proof;

  const hash = sha256Hex(JSON.stringify(clone));

  receipt.metadata = receipt.metadata || {};
  receipt.metadata.proof = {
    alg: "ed25519-sha256",
    canonical: "json-stringify",
    hash_sha256: hash,
    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || "cl-fetch-live"
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

/* -------------------- ENS resolution -------------------- */

async function resolveSchemasFromENS() {
  const rpc = process.env.ETH_RPC_URL?.trim();
  const ens = process.env.ENS_NAME?.trim();
  if (!rpc || !ens) throw new Error("Missing ETH_RPC_URL or ENS_NAME");

  const provider = new ethers.JsonRpcProvider(rpc);
  const resolver = await provider.getResolver(ens);
  if (!resolver) throw new Error(`No resolver for ${ens}`);

  const reqUrl = await resolver.getText("cl.schema.request");
  const rcptUrl = await resolver.getText("cl.schema.receipt");
  if (!reqUrl || !rcptUrl) throw new Error("ENS missing schema TXT records");

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
  loadSchema: async (uri) => (await fetch(uri)).json()
});
addFormats(ajv);

const validateReq = await ajv.compileAsync(await (await fetch(REQ_URL)).json());
const validateRcpt = await ajv.compileAsync(await (await fetch(RCPT_URL)).json());

/* -------------------- routes -------------------- */

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.get("/debug/env", (_req, res) => {
  res.json({
    has_priv: Boolean(process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM),
    has_pub: Boolean(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM),
    signer_id: process.env.RECEIPT_SIGNER_ID || null,
    ens_name: process.env.ENS_NAME || null
  });
});

app.post("/fetch/v1.0.0", async (req, res) => {
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

    // hard timeout so it never hangs -> no Railway 502 timeouts
    const controller = new AbortController();
    const timeout_ms = 8000;
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
      trace: {
        trace_id,
        started_at,
        completed_at: new Date().toISOString()
      },
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
    // Always respond (never hang)
    const receipt = {
      status: "error",
      x402: {
        entry: "x402://fetchagent.eth/fetch/v1.0.0",
        verb: "fetch",
        version: "1.0.0"
      },
      trace: {
        trace_id: id("trace"),
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString()
      },
      error: {
        code: "RUNTIME_ERROR",
        message: String(e?.message ?? e),
        retryable: true
      },
      result: { items: [] }
    };

    attachReceiptProof(receipt);

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

