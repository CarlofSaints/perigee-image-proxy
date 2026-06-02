/**
 * Perigee login + image proxy helpers.
 *
 * Handles Drupal form-based authentication and image fetching
 * with session cookie forwarding.
 */

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const BROWSER_HEADERS = {
  "User-Agent": UA,
  Accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.9",
};

/* ── Cookie Helpers ──────────────────────────────────── */

function extractCookies(setCookieHeaders: string[]): string {
  const parts: string[] = [];
  for (const sc of setCookieHeaders) {
    const nv = sc.split(";")[0].trim();
    if (nv && nv.includes("=")) parts.push(nv);
  }
  return parts.join("; ");
}

function extractSessCookie(setCookieHeaders: string[]): string | null {
  for (const sc of setCookieHeaders) {
    const nv = sc.split(";")[0].trim();
    if (nv.startsWith("SSESS")) return nv;
  }
  return null;
}

/**
 * Parse Set-Cookie from a fetch Response.
 * Node's fetch returns getSetCookie() as an array.
 */
function getSetCookieArray(res: Response): string[] {
  // Node 18+ fetch Response has getSetCookie()
  if (typeof (res.headers as any).getSetCookie === "function") {
    return (res.headers as any).getSetCookie();
  }
  // Fallback: get raw header (comma-joined, fragile)
  const raw = res.headers.get("set-cookie");
  if (!raw) return [];
  return raw.split(/,(?=[^ ])/);
}

/* ── Login ───────────────────────────────────────────── */

export interface LoginResult {
  ok: boolean;
  cookie?: string;
  error?: string;
  debug?: Record<string, unknown>;
}

export async function perigeeLogin(
  username: string,
  password: string,
  debug = false
): Promise<LoginResult> {
  const diag: Record<string, unknown> = {};

  try {
    // Step 1: GET login page — extract form tokens + anonymous cookie
    const pageRes = await fetch(
      "https://live.perigeeportal.co.za/user/login",
      {
        headers: BROWSER_HEADERS,
        redirect: "manual",
      }
    );
    const pageHtml = await pageRes.text();
    const pageSC = getSetCookieArray(pageRes);

    if (debug) {
      diag.step1 = {
        status: pageRes.status,
        contentLength: pageHtml.length,
        hasLoginForm: pageHtml.includes("user-login"),
        htmlSnippet: pageHtml.substring(0, 500),
        setCookieCount: pageSC.length,
      };
    }

    if (pageRes.status === 403) {
      return {
        ok: false,
        error: `Perigee returned 403 on login page — this IP may be blocked`,
        ...(debug ? { debug: diag } : {}),
      };
    }

    // Extract form tokens (try both attribute orders)
    const buildIdMatch =
      pageHtml.match(/name="form_build_id"\s+value="([^"]+)"/) ||
      pageHtml.match(/value="([^"]+)"\s+name="form_build_id"/);
    const tokenMatch =
      pageHtml.match(/name="form_token"\s+value="([^"]+)"/) ||
      pageHtml.match(/value="([^"]+)"\s+name="form_token"/);

    const pageCookies = extractCookies(pageSC);

    if (debug) {
      diag.step1_tokens = {
        form_build_id: buildIdMatch ? buildIdMatch[1] : "NOT FOUND",
        form_token: tokenMatch ? tokenMatch[1] : "NOT FOUND",
        pageCookies: pageCookies || "NONE",
      };
    }

    // Step 2: POST credentials
    const formBody = new URLSearchParams();
    formBody.append("name", username);
    formBody.append("pass", password);
    formBody.append("form_id", "user_login");
    formBody.append("op", "Log in");
    if (buildIdMatch) formBody.append("form_build_id", buildIdMatch[1]);
    if (tokenMatch) formBody.append("form_token", tokenMatch[1]);

    const postHeaders: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      ...BROWSER_HEADERS,
      Referer: "https://live.perigeeportal.co.za/user/login",
      Origin: "https://live.perigeeportal.co.za",
    };
    if (pageCookies) postHeaders["Cookie"] = pageCookies;

    if (debug) {
      const fields = Object.fromEntries(formBody.entries());
      fields.pass = "***";
      diag.step2_request = {
        hasCookies: !!pageCookies,
        hasFormBuildId: !!buildIdMatch,
        hasFormToken: !!tokenMatch,
        formFields: fields,
      };
    }

    const loginRes = await fetch(
      "https://live.perigeeportal.co.za/user/login",
      {
        method: "POST",
        headers: postHeaders,
        body: formBody.toString(),
        redirect: "manual",
      }
    );

    const loginBody = await loginRes.text();
    const loginSC = getSetCookieArray(loginRes);

    if (debug) {
      diag.step2_response = {
        status: loginRes.status,
        location: loginRes.headers.get("location"),
        setCookieCount: loginSC.length,
        setCookieHeaders: loginSC.map((s) => s.substring(0, 80) + "..."),
        contentLength: loginBody.length,
        bodySnippet: loginBody.substring(0, 300),
      };
    }

    // Extract SSESS cookie
    const sessCookie = extractSessCookie(loginSC);

    if (sessCookie) {
      return {
        ok: true,
        cookie: sessCookie,
        ...(debug ? { debug: diag } : {}),
      };
    }

    // Determine error reason
    const status = loginRes.status;
    let error: string;
    if (status === 200) {
      if (loginBody.includes("Sorry, unrecognized")) {
        error = "Invalid username or password";
      } else if (loginBody.includes("Access denied")) {
        error = "Access denied by Perigee";
      } else {
        error = "Login returned 200 (form re-displayed) — likely invalid credentials";
      }
    } else if (status === 302 || status === 303) {
      const loc = loginRes.headers.get("location") || "";
      error = `Redirected to ${loc} but no session cookie was set`;
    } else if (status === 403) {
      error = "Perigee returned 403 — this IP may be blocked";
    } else {
      error = `Login returned HTTP ${status} — no session cookie`;
    }

    return { ok: false, error, ...(debug ? { debug: diag } : {}) };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: `Login error: ${msg}`,
      ...(debug ? { debug: diag } : {}),
    };
  }
}

/* ── Image Proxy ─────────────────────────────────────── */

export interface ImageResult {
  ok: boolean;
  data?: Buffer;
  contentType?: string;
  status?: number;
  error?: string;
}

export async function fetchPerigeeImage(
  imageUrl: string,
  sessionCookie: string
): Promise<ImageResult> {
  if (!imageUrl.startsWith("https://live.perigeeportal.co.za")) {
    return { ok: false, error: "Disallowed domain", status: 403 };
  }

  try {
    const headers: Record<string, string> = {
      "User-Agent": UA,
      Accept: "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
    };
    if (sessionCookie) headers["Cookie"] = sessionCookie;

    const res = await fetch(imageUrl, { headers });

    if (!res.ok) {
      return {
        ok: false,
        error: `Upstream error: ${res.status}`,
        status: res.status,
      };
    }

    const contentType = res.headers.get("content-type") || "image/jpeg";
    const arrayBuffer = await res.arrayBuffer();

    return {
      ok: true,
      data: Buffer.from(arrayBuffer),
      contentType,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, error: `Fetch error: ${msg}` };
  }
}
