/* Minimal inbound API key authentication for Hono.
   - Enable by setting INBOUND_API_KEY or INBOUND_API_KEYS (comma-separated).
   - Clients can send the key via:
     - Authorization: Bearer <key>
     - Authorization: <key>            (fallback if no scheme)
     - X-API-Key: <key>
   - Optionally skip certain paths with INBOUND_AUTH_SKIP_PATHS, comma-separated.
*/
import type { MiddlewareHandler } from "hono"

function loadAllowedKeys(): Set<string> {
  const keys = new Set<string>()
  const single = process.env.INBOUND_API_KEY?.trim()
  if (single) keys.add(single)

  const list = process.env.INBOUND_API_KEYS
  if (list) {
    for (const k of list.split(",").map((s) => s.trim()).filter(Boolean)) {
      keys.add(k)
    }
  }
  return keys
}

function loadSkipPaths(): Set<string> {
  const raw = process.env.INBOUND_AUTH_SKIP_PATHS ?? ""
  const set = new Set<string>()
  for (const p of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    set.add(p)
  }
  return set
}

function extractIncomingKey(c: Parameters<MiddlewareHandler>[0]): string | undefined {
  const auth = c.req.header("authorization")
  const xApiKey = c.req.header("x-api-key")

  if (auth) {
    const lower = auth.toLowerCase()
    if (lower.startsWith("bearer ")) {
      return auth.slice(7).trim()
    }
    // If Authorization present without a known scheme, treat the whole value as key (fallback)
    if (!lower.startsWith("basic ") && !lower.startsWith("digest ")) {
      return auth.trim()
    }
  }
  if (xApiKey) return xApiKey.trim()
  return undefined
}

export function inboundAuth(): MiddlewareHandler {
  const allowedKeys = loadAllowedKeys()
  const skipPaths = loadSkipPaths()

  return async (c, next) => {
    // If no keys configured, do nothing (backward compatible)
    if (allowedKeys.size === 0) return next()

    const url = new URL(c.req.url)
    const path = url.pathname

    // Allow skipping specific paths if desired (e.g., "/usage")
    if (skipPaths.has(path)) return next()

    const key = extractIncomingKey(c)
    if (!key || !allowedKeys.has(key)) {
      c.header('WWW-Authenticate', 'Bearer realm="copilot-api", charset="UTF-8"')
      return c.json({ error: "Unauthorized" }, 401)
    }

    return next()
  }
}
