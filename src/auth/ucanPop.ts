import type { JtiCache } from './jtiCache'
import {
  createSignedAuthHeader,
  verifySignedAuthHeader,
} from './signedAuthHeader'
import type { PopVerifyResult } from './types'

/**
 * UCAN-PoP is a thin naming layer over the generic signed-auth header.
 * The only semantic addition: the payload's `did` MUST equal the audience of
 * the accompanying UCAN. Because `verifySignedAuthHeader` already enforces
 * `payload.did === expectedDid`, the wrapper simply pins the naming.
 */

export interface CreateUcanPopHeaderOptions {
  /** Ed25519 private key belonging to `ucanAud`. */
  privateKey: CryptoKey
  /** The `aud` field of the UCAN this PoP accompanies. */
  ucanAud: string
  method: string
  path: string
  rawQuery: string
  body: string
  now?: number
  jti?: string
  ttlMs?: number
}

/**
 * Build the `X-UCAN-PoP` header value for a request whose UCAN has audience
 * `ucanAud`. The presenter proves possession of `ucanAud`'s private key and
 * binds the signature to (method, path, rawQuery, body).
 */
export function createUcanPopHeader(opts: CreateUcanPopHeaderOptions): Promise<string> {
  return createSignedAuthHeader({
    privateKey: opts.privateKey,
    did: opts.ucanAud,
    method: opts.method,
    path: opts.path,
    rawQuery: opts.rawQuery,
    body: opts.body,
    now: opts.now,
    jti: opts.jti,
    ttlMs: opts.ttlMs,
  })
}

export interface VerifyUcanPopOptions {
  /** Value of the `X-UCAN-PoP` header from the request. */
  headerValue: string
  /** Audience of the already-verified UCAN. */
  expectedUcanAud: string
  method: string
  path: string
  rawQuery: string
  body: string
  now?: number
  seenJtis?: JtiCache
  clockSkewMs?: number
}

/**
 * Verify an `X-UCAN-PoP` header. Delegates to `verifySignedAuthHeader`, which
 * enforces `payload.did === expectedUcanAud` — the wrapper only pins the name.
 */
export function verifyUcanPop(opts: VerifyUcanPopOptions): Promise<PopVerifyResult> {
  return verifySignedAuthHeader({
    headerValue: opts.headerValue,
    expectedDid: opts.expectedUcanAud,
    method: opts.method,
    path: opts.path,
    rawQuery: opts.rawQuery,
    body: opts.body,
    now: opts.now,
    seenJtis: opts.seenJtis,
    clockSkewMs: opts.clockSkewMs,
  })
}
