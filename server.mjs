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
    signer_id: process.env.RECEIPT_SIGNER_ID || "cl-fetch-live"
  };

  try {
    receipt.metadata.proof.signature_b64 = signEd25519(hash);
    const pub = readPemEnv("RECEIPT_SIGNING_PUBLIC_KEY_PEM");
    if (pub) receipt.metadata.proof.public_key_pem = pub;
  } catch (e) {
    receipt.metadata.proof.signature_error = String(e?.message ?? e);
  }
}

/* -------------------- ENS resolution -------------------- */

async function resolveSchemasFromENS() {
  const rpc = process.env.ETH_RPC_URL;
  const ens = process.env.ENS_NAME;
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

app.get("/health", (_req, res) => res.send("ok"));

app.get("/debug/env", (_req, res) => {
  res.json({
    has_priv: Boolean(process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM),
    has_pub: Boolean(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM),
    signer_id: process.env.RECEIPT_SIGNER_ID || null
  });
});

app.post("/fetch/v1.0.0", async (req, res) => {
  try {
    if (!validateReq(req.body)) {
      return res.status(400).json({
        error: "request schema invalid",
        details: validateReq.errors
      });
    }

    const traceId = id("trace");
    const started = new Date().toISOString();

    const r = await fetch(req.body.source);
    const text = await r.text();

    const receipt = {
      status: "success",
      x402: req.body.x402,
      trace: {
        trace_id: traceId,
        started_at: started,
        completed_at: new Date().toISOString()
      },
      result: {
        items: [{
          source: req.body.source,
          ok: r.ok,
          http_status: r.status,
          body_preview: text.slice(0, 2000)
        }]
      }
    };

    attachReceiptProof(receipt);

    if (!validateRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid",
        details: validateRcpt.errors
      });
    }

    res.json(receipt);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/* -------------------- start -------------------- */

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("listening on", port));
