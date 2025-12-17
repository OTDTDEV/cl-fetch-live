console.log("🔥 SERVER.MJS BOOTED 🔥");
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
  // For v1: stable enough for now (your receipts already rely on this)
  // If you want *true* canonical JSON later, use a canonicalizer lib.
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
  // hash should be computed without the proof itself
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

/* --*
