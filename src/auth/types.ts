/**
 * Signed-auth PoP payload — the frozen shape shared by DID-Auth (post-migration)
 * and UCAN-PoP.
 *
 * Wire encoding: `<base64url(json)>.<base64url(sig)>`.
 * Signature is Ed25519 over the raw JSON bytes (before base64url wrapping).
 */
export interface PopPayload {
  /** Presenter's DID. For UCAN-PoP this MUST equal the UCAN `aud`. */
  did: string
  /** Wall-clock millisecond epoch at signing time. */
  timestamp: number
  /** Absolute expiration in ms epoch. Server rejects when `now > exp`. */
  exp: number
  /** UUID v4. Server maintains a TTL-cache of seen jtis for replay defence. */
  jti: string
  /** base64url(SHA-256(METHOD + "\n" + PATH + "\n" + rawQuery + "\n" + body)). */
  requestHash: string
}

/**
 * Header name for the PoP companion header on UCAN-authed routes.
 * Value is the wire-encoded signed payload.
 */
export const POP_HEADER_NAME = 'X-UCAN-PoP'

/**
 * Verifier failure reasons. Pinned as string constants so e2e specs can assert
 * on them without threading enum imports through Playwright wire assertions.
 */
export const POP_ERROR_MESSAGES = {
  MALFORMED: 'PoP malformed',
  EXPIRED: 'Expired PoP',
  FUTURE_TIMESTAMP: 'PoP timestamp is in the future',
  LIFETIME_EXCEEDED: 'PoP lifetime exceeds server maximum',
  REPLAY: 'PoP replay detected',
  AUDIENCE_MISMATCH: 'PoP does not match UCAN audience',
  SIGNATURE_INVALID: 'PoP signature invalid',
  REQUEST_MISMATCH: 'PoP request mismatch',
} as const

export type PopErrorMessage = (typeof POP_ERROR_MESSAGES)[keyof typeof POP_ERROR_MESSAGES]

/**
 * Discriminated-union result of verifying a signed auth header. On success the
 * verified payload is returned; on failure the pinnable reason is returned.
 */
export type PopVerifyResult =
  | { ok: true; payload: PopPayload }
  | { ok: false; reason: PopErrorMessage }

/**
 * JSON claims carried alongside the common proof-of-possession fields.
 *
 * Protocol-specific wrappers may add claims, but cannot replace any of the
 * PoP fields. The complete object is covered by the Ed25519 signature.
 */
export type SignedAuthAdditionalPayload = Readonly<Record<string, unknown>>
