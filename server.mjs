import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.post("/fetch/v1", async (req, res) => {
  const url = req.body?.url;
  if (!url) return res.status(400).json({ error: "missing url" });

  const r = await fetch(url, { method: "GET" });
  const text = await r.text();

  // simple “receipt-like” response
  return res.json({
    request: { url },
    result: { ok: r.ok, status: r.status, body_preview: text.slice(0, 300) }
  });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`listening on ${port}`));
