import "dotenv/config";
import express from "express";
import cors from "cors";
import { apiKeyAuth } from "./auth";
import { perigeeLogin, fetchPerigeeImage } from "./perigee";

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

app.use(cors());
app.use(express.json({ limit: "1mb" }));

/* ── Public health checks ────────────────────────────── */

app.get("/ping", (_req, res) => {
  res.send("pong");
});

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

/* ── Protected routes (require x-api-key) ────────────── */

app.use(apiKeyAuth);

/**
 * POST /login
 * Body: { username, password, debug?: boolean }
 * Returns: { ok, cookie?, error?, debug? }
 */
app.post("/login", async (req, res) => {
  const { username, password, debug } = req.body || {};

  if (!username || !password) {
    res.status(400).json({ error: "Missing username or password" });
    return;
  }

  const result = await perigeeLogin(username, password, !!debug);
  res.status(result.ok ? 200 : 401).json(result);
});

/**
 * GET /image?url=<perigee-image-url>
 * Header: x-perigee-cookie: SSESS...=value
 * Returns: image binary
 */
app.get("/image", async (req, res) => {
  const imageUrl = req.query.url as string;
  const cookie = req.headers["x-perigee-cookie"] as string;

  if (!imageUrl) {
    res.status(400).json({ error: "Missing url query parameter" });
    return;
  }

  if (!cookie) {
    res.status(400).json({ error: "Missing x-perigee-cookie header" });
    return;
  }

  const result = await fetchPerigeeImage(imageUrl, cookie);

  if (!result.ok || !result.data) {
    res.status(result.status || 502).json({ error: result.error });
    return;
  }

  res.set("Content-Type", result.contentType || "image/jpeg");
  res.set("Cache-Control", "public, max-age=86400");
  res.send(result.data);
});

/**
 * GET /test-access
 * Quick check: can this server reach Perigee's login page?
 */
app.get("/test-access", async (_req, res) => {
  try {
    const r = await fetch("https://live.perigeeportal.co.za/user/login", {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      },
      redirect: "manual",
    });
    res.json({
      status: r.status,
      ok: r.status === 200,
      hint:
        r.status === 200
          ? "Perigee is reachable from this server — login should work"
          : r.status === 403
            ? "403 Forbidden — Perigee is blocking this server's IP"
            : `Unexpected status ${r.status}`,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    res.json({ status: 0, ok: false, error: msg });
  }
});

/* ── Root ─────────────────────────────────────────────── */

app.get("/", (_req, res) => {
  res.json({
    name: "perigee-image-proxy",
    version: "1.0.0",
    endpoints: {
      "GET /ping": "Health ping (public)",
      "GET /health": "Health check (public)",
      "GET /test-access": "Check if Perigee is reachable (requires x-api-key)",
      "POST /login": "Authenticate with Perigee (requires x-api-key)",
      "GET /image?url=...": "Proxy Perigee image (requires x-api-key + x-perigee-cookie)",
    },
  });
});

/* ── Start ────────────────────────────────────────────── */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`perigee-image-proxy listening on 0.0.0.0:${PORT}`);
});
