import type {
  UcanHeader,
  UcanPayload,
  DecodedUcan,
  EncodedUcan,
  CreateUcanParams,
  SignFn,
} from './types'
import { base64urlEncode, base64urlDecode, encodeJsonBase64url, decodeJsonBase64url } from './encoding'

const HEADER: UcanHeader = { alg: 'EdDSA', typ: 'JWT' }

/**
 * Create and sign a new UCAN token.
 *
 * @param params - Token parameters (issuer, audience, capabilities, etc.)
 * @param sign - Ed25519 signing function for the issuer's private key
 * @returns Encoded UCAN token (header.payload.signature)
 */
export async function createUcan(params: CreateUcanParams, sign: SignFn): Promise<EncodedUcan> {
  const now = Math.floor(Date.now() / 1000)

  const payload: UcanPayload = {
    ucv: '1.0',
    iss: params.issuer,
    aud: params.audience,
    cap: params.capabilities,
    exp: params.expiration,
    iat: now,
    prf: params.proofs ?? [],
  }

  if (params.facts) {
    payload.fct = params.facts
  }

  if (params.nonce) {
    payload.nnc = params.nonce
  } else {
    const nonceBytes = new Uint8Array(12)
    crypto.getRandomValues(nonceBytes)
    payload.nnc = base64urlEncode(nonceBytes)
  }

  const headerB64 = encodeJsonBase64url(HEADER)
  const payloadB64 = encodeJsonBase64url(payload)
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`)

  const signature = await sign(signingInput)
  const signatureB64 = base64urlEncode(signature)

  return `${headerB64}.${payloadB64}.${signatureB64}`
}

/**
 * Decode a UCAN token without verifying the signature.
 * Use `verifyUcan` for full verification.
 */
export function decodeUcan(token: EncodedUcan): DecodedUcan {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('Invalid UCAN: expected 3 dot-separated parts')
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string]

  const header = decodeJsonBase64url<UcanHeader>(headerB64)
  if (header.alg !== 'EdDSA') {
    throw new Error(`Unsupported algorithm: ${header.alg} (expected EdDSA)`)
  }
  if (header.typ !== 'JWT') {
    throw new Error(`Unsupported type: ${header.typ} (expected JWT)`)
  }

  const payload = decodeJsonBase64url<UcanPayload>(payloadB64)
  if (payload.ucv !== '1.0') {
    throw new Error(`Unsupported UCAN version: ${payload.ucv} (expected 1.0)`)
  }

  const signature = base64urlDecode(signatureB64)

  return { header, payload, signature, raw: token }
}

/**
 * Extract the signing input from an encoded UCAN (header.payload without signature).
 * Used for signature verification.
 */
export function getSigningInput(token: EncodedUcan): Uint8Array {
  const lastDot = token.lastIndexOf('.')
  if (lastDot === -1) {
    throw new Error('Invalid UCAN: no dot separator found')
  }
  return new TextEncoder().encode(token.slice(0, lastDot))
}
