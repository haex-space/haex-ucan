import { base64urlEncode } from '../encoding'

/**
 * Canonicalise (method, path, rawQuery, body) and return base64url(SHA-256(canonical)).
 *
 * Canonical form: `METHOD + "\n" + PATH + "\n" + RAW_QUERY + "\n" + BODY`.
 *
 * Rules — client and server MUST agree byte-exactly, else every request 401s:
 *  - `method` is uppercased ASCII.
 *  - `path` is passed verbatim (no percent-decoding, no trailing-slash normalisation).
 *  - `rawQuery` is everything after `?` (empty string if none). Not sorted, not re-encoded.
 *  - `body` is the raw request body as a UTF-8 string (empty string if none).
 *  - Separator is a single LF (0x0A) between the four fields.
 */
export async function computeRequestHash(
  method: string,
  path: string,
  rawQuery: string,
  body: string,
): Promise<string> {
  const canonical = `${method.toUpperCase()}\n${path}\n${rawQuery}\n${body}`
  const bytes = new TextEncoder().encode(canonical)
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>)
  return base64urlEncode(new Uint8Array(digest))
}
