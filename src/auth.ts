import { Request, Response, NextFunction } from "express";

/**
 * Middleware: validate x-api-key header against API_KEY env var.
 */
export function apiKeyAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const key = req.headers["x-api-key"];
  const expected = process.env.API_KEY;

  if (!expected) {
    res.status(500).json({ error: "API_KEY not configured on server" });
    return;
  }

  if (!key || key !== expected) {
    res.status(401).json({ error: "Invalid or missing API key" });
    return;
  }

  next();
}
