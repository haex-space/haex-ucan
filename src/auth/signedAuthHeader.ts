import { base64urlDecode, base64urlEncode } from '../encoding'
import { didToRawPublicKey } from '../multibase'
import { computeRequestHash } from './requestHash'
import type { JtiCache } from './jtiCache'
import type { PopPayload, PopVerifyResult } from './types'
import { POP_ERROR_MESSAGES } from './types'

/** Default PoP validity window. Matches DID-Auth (60 s). */
export const DEFAULT_POP_TTL_MS = 60_000

/**
 * Default clock-skew tolerance for `payload.timestamp > now` checks. Small on
 * purpose — this is the *future* direction; loose past tolerance is handled by
 * the (much wider) `exp` window.
 */
export const DEFAULT_POP_CLOCK_SKEW_MS = 5_000

/**
 * Server-side cap on `payload.exp - payload.timestamp`. Prevents a caller from
 * declaring an arbitrarily long lifetime — which would (a) let a captured proof
 * remain replay-eligible far beyond the intended window and (b) pin the jti in
 * the replay cache for equally long, opening a memory-DoS via unique jtis.
 * Defaults to `DEFAULT_POP_TTL_MS` so a caller that opts into a longer client
 * TTL must be met by a server that also opts in.
 */
export const DEFAULT_MAX_POP_LIFETIME_MS = DEFAULT_POP_TTL_MS

export interface CreateSignedAuthHeaderOptions {
  /** Ed25519 private key belonging to `did`. */
  privateKey: CryptoKey
  /** DID whose public key the verifier will use. */
  did: string
  /** HTTP method — will be uppercased inside `computeRequestHash`. */
  method: string
  /** Request path (no host, no query). */
  path: string
  /** Everything after `?` (empty if none). Not sorted, not re-encoded. */
  rawQuery: string
  /** Request body as a UTF-8 string (empty if none). */
  body: string
  /** Override `Date.now()` — useful for tests and for signing pre-flighted requests. */
  now?: number
  /** Explicit `jti`. Defaults to a fresh UUID v4. */
  jti?: string
  /** Explicit validity window in ms. Defaults to `DEFAULT_POP_TTL_MS`. */
  ttlMs?: number
}

/**
 * Sign a fresh `PopPayload` and return the wire-encoded header value
 * `<base64url(json)>.<base64url(sig)>`.
 */
export async function createSignedAuthHeader(opts: CreateSignedAuthHeaderOptions): Promise<string> {
  const now = opts.now ?? Date.now()
  const ttlMs = opts.ttlMs ?? DEFAULT_POP_TTL_MS
  const requestHash = await computeRequestHash(opts.method, opts.path, opts.rawQuery, opts.body)

  const payload: PopPayload = {
    did: opts.did,
    timestamp: now,
    exp: now + ttlMs,
    jti: opts.jti ?? crypto.randomUUID(),
    requestHash,
  }

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload))
  const signatureRaw = await crypto.subtle.sign(
    'Ed25519',
    opts.privateKey,
    payloadBytes as Uint8Array<ArrayBuffer>,
  )
  const signature = new Uint8Array(signatureRaw)

  return `${base64urlEncode(payloadBytes)}.${base64urlEncode(signature)}`
}

export interface VerifySignedAuthHeaderOptions {
  /** Wire-encoded header value `<base64url(json)>.<base64url(sig)>`. */
  headerValue: string
  /** DID the verifier expects the payload to belong to. */
  expectedDid: string
  method: string
  path: string
  rawQuery: string
  body: string
  /** Override `Date.now()` — for tests. */
  now?: number
  /** Optional replay-defence cache. When present, seen jtis are rejected. */
  seenJtis?: JtiCache
  /** Tolerance for future-clock drift. Defaults to `DEFAULT_POP_CLOCK_SKEW_MS`. */
  clockSkewMs?: number
  /** Max accepted `payload.exp - payload.timestamp`. Defaults to `DEFAULT_MAX_POP_LIFETIME_MS`. */
  maxLifetimeMs?: number
}

/**
 * Verify a signed auth header. Returns a discriminated union so callers can
 * surface pinnable failure reasons without stringly-typed comparisons.
 *
 * Check order — cheapest structural checks first, signature (WebCrypto verify)
 * last, and `jti` insertion strictly *after* signature success so invalid
 * signatures can't burn attacker-chosen jtis:
 *
 *  1. structural / base64 parse
 *  2. `payload.did === expectedDid`  (audience)
 *  3. `payload.timestamp <= now + skew` (future drift)
 *  4. `payload.exp - payload.timestamp <= maxLifetimeMs` (declared lifetime cap)
 *  5. `now <= payload.exp`  (expiration)
 *  6. `payload.requestHash === computeRequestHash(...)`
 *  7. Ed25519 signature verify against `didToRawPublicKey(expectedDid)`
 *  8. `!seenJtis.has(jti)`; then `seenJtis.add(jti, payload.exp)` — retention
 *     matches the accepted proof's exp so the entry cannot evict before the
 *     window closes.
 */
export async function verifySignedAuthHeader(
  opts: VerifySignedAuthHeaderOptions,
): Promise<PopVerifyResult> {
  const now = opts.now ?? Date.now()
  const skew = opts.clockSkewMs ?? DEFAULT_POP_CLOCK_SKEW_MS
  const maxLifetimeMs = opts.maxLifetimeMs ?? DEFAULT_MAX_POP_LIFETIME_MS

  const parts = opts.headerValue.split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { ok: false, reason: POP_ERROR_MESSAGES.MALFORMED }
  }
  const [encPayload, encSig] = parts

  let payload: PopPayload
  let payloadBytes: Uint8Array
  try {
    payloadBytes = base64urlDecode(encPayload)
    const decoded: unknown = JSON.parse(new TextDecoder().decode(payloadBytes))
    if (!isPopPayload(decoded)) {
      return { ok: false, reason: POP_ERROR_MESSAGES.MALFORMED }
    }
    payload = decoded
  }
  catch {
    return { ok: false, reason: POP_ERROR_MESSAGES.MALFORMED }
  }

  if (payload.did !== opts.expectedDid) {
    return { ok: false, reason: POP_ERROR_MESSAGES.AUDIENCE_MISMATCH }
  }
  if (payload.timestamp > now + skew) {
    return { ok: false, reason: POP_ERROR_MESSAGES.FUTURE_TIMESTAMP }
  }
  if (payload.exp - payload.timestamp > maxLifetimeMs) {
    return { ok: false, reason: POP_ERROR_MESSAGES.LIFETIME_EXCEEDED }
  }
  if (now > payload.exp) {
    return { ok: false, reason: POP_ERROR_MESSAGES.EXPIRED }
  }

  const expectedHash = await computeRequestHash(opts.method, opts.path, opts.rawQuery, opts.body)
  if (payload.requestHash !== expectedHash) {
    return { ok: false, reason: POP_ERROR_MESSAGES.REQUEST_MISMATCH }
  }

  let signatureBytes: Uint8Array
  try {
    signatureBytes = base64urlDecode(encSig)
  }
  catch {
    return { ok: false, reason: POP_ERROR_MESSAGES.MALFORMED }
  }

  let signatureValid = false
  try {
    const publicKeyBytes = didToRawPublicKey(opts.expectedDid)
    const key = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes as Uint8Array<ArrayBuffer>,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    signatureValid = await crypto.subtle.verify(
      'Ed25519',
      key,
      signatureBytes as Uint8Array<ArrayBuffer>,
      payloadBytes as Uint8Array<ArrayBuffer>,
    )
  }
  catch {
    signatureValid = false
  }
  if (!signatureValid) {
    return { ok: false, reason: POP_ERROR_MESSAGES.SIGNATURE_INVALID }
  }

  if (opts.seenJtis) {
    if (opts.seenJtis.has(payload.jti)) {
      return { ok: false, reason: POP_ERROR_MESSAGES.REPLAY }
    }
    opts.seenJtis.add(payload.jti, payload.exp)
  }

  return { ok: true, payload }
}

function isPopPayload(value: unknown): value is PopPayload {
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v.did === 'string'
    && typeof v.timestamp === 'number'
    && typeof v.exp === 'number'
    && typeof v.jti === 'string'
    && typeof v.requestHash === 'string'
  )
}
