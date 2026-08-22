import { base64urlDecode } from '../encoding'
import type { UcanPayload } from '../types'
import { POP_HEADER_NAME } from './types'
import { createUcanPopHeader } from './ucanPop'

/**
 * Resolves the private key for a given DID. The vault provides a concrete
 * implementation that looks the key up in its identity store and imports it
 * as a WebCrypto Ed25519 `CryptoKey`.
 */
export type PrivateKeyResolver = (did: string) => Promise<CryptoKey>

/**
 * `fetch()` wrapper that attaches:
 *  - `Authorization: UCAN <token>`
 *  - `X-UCAN-PoP: <signed-payload>`
 *
 * The audience is decoded directly from the UCAN — callers never say who they
 * are, they hand over the token and the resolver picks the matching key.
 *
 * Body constraint: strings only. UCAN-authed routes carry structured DB rows
 * (see plan §B.1a "Domain rationale for the cap"); large binary payloads go
 * through the file-sync transport and are out of scope for PoP.
 */
export async function fetchWithUcanPop(
  url: string,
  ucanToken: string,
  resolvePrivateKey: PrivateKeyResolver,
  options: RequestInit = {},
): Promise<Response> {
  const aud = extractUcanAudience(ucanToken)
  const privateKey = await resolvePrivateKey(aud)

  const method = (options.method ?? 'GET').toUpperCase()
  const body = normaliseBody(options.body)

  const parsed = new URL(url, globalThis.location?.href)
  const path = parsed.pathname
  const rawQuery = parsed.search.startsWith('?') ? parsed.search.slice(1) : parsed.search

  const popHeader = await createUcanPopHeader({
    privateKey,
    ucanAud: aud,
    method,
    path,
    rawQuery,
    body,
  })

  const headers = new Headers(options.headers)
  headers.set('Authorization', `UCAN ${ucanToken}`)
  headers.set(POP_HEADER_NAME, popHeader)
  if (body.length > 0 && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  return fetch(url, {
    ...options,
    method,
    headers,
    body: body.length > 0 ? body : null,
  })
}

function extractUcanAudience(token: string): string {
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new Error('Invalid UCAN token: expected header.payload.signature')
  }
  const encodedPayload = parts[1]
  if (!encodedPayload) {
    throw new Error('Invalid UCAN token: missing payload segment')
  }
  const bytes = base64urlDecode(encodedPayload)
  const payload = JSON.parse(new TextDecoder().decode(bytes)) as UcanPayload
  if (typeof payload.aud !== 'string' || payload.aud.length === 0) {
    throw new Error('Invalid UCAN token: missing aud')
  }
  return payload.aud
}

function normaliseBody(body: BodyInit | null | undefined): string {
  if (body == null) return ''
  if (typeof body === 'string') return body
  throw new TypeError(
    'fetchWithUcanPop only accepts string bodies. UCAN-authed routes carry structured DB rows; '
    + 'other body types would make client/server request-hash agreement unreliable.',
  )
}
