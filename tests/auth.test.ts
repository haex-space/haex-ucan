import { describe, expect, it } from 'vitest'
import {
  base58btcEncode,
  computeRequestHash,
  createJtiTtlCache,
  createSignedAuthHeader,
  DEFAULT_POP_TTL_MS,
  POP_ERROR_MESSAGES,
  verifySignedAuthHeader,
} from '../src'

interface TestIdentity {
  did: string
  privateKey: CryptoKey
}

async function generateIdentity(): Promise<TestIdentity> {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  const multicodec = new Uint8Array(2 + rawPub.length)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(rawPub, 2)
  const did = `did:key:z${base58btcEncode(multicodec)}`
  return { did, privateKey: kp.privateKey }
}

const METHOD = 'POST'
const PATH = '/spaces/test-space/invite-tokens'
const RAW_QUERY = 'ttl=3600&role=reader'
const BODY = JSON.stringify({ cap: 'read' })

describe('UCAN-PoP shared primitives (§A.3)', () => {
  it('1. sign → verify roundtrip', async () => {
    const id = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.payload.did).toBe(id.did)
      expect(result.payload.requestHash).toBe(await computeRequestHash(METHOD, PATH, RAW_QUERY, BODY))
      expect(result.payload.exp - result.payload.timestamp).toBe(DEFAULT_POP_TTL_MS)
    }
  })

  it('2. expired (now > exp) is rejected', async () => {
    const id = await generateIdentity()
    const past = Date.now() - 10 * 60_000
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
      now: past,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.EXPIRED })
  })

  it('3. jti replay within window is rejected', async () => {
    const id = await generateIdentity()
    const jtiCache = createJtiTtlCache({ ttlMs: 60_000, sweepIntervalMs: 60_000 })
    try {
      const header = await createSignedAuthHeader({
        privateKey: id.privateKey,
        did: id.did,
        method: METHOD,
        path: PATH,
        rawQuery: RAW_QUERY,
        body: BODY,
      })

      const first = await verifySignedAuthHeader({
        headerValue: header,
        expectedDid: id.did,
        method: METHOD,
        path: PATH,
        rawQuery: RAW_QUERY,
        body: BODY,
        seenJtis: jtiCache,
      })
      expect(first.ok).toBe(true)

      const second = await verifySignedAuthHeader({
        headerValue: header,
        expectedDid: id.did,
        method: METHOD,
        path: PATH,
        rawQuery: RAW_QUERY,
        body: BODY,
        seenJtis: jtiCache,
      })
      expect(second).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.REPLAY })
    }
    finally {
      jtiCache.destroy()
    }
  })

  it('4. mismatched did (audience) is rejected', async () => {
    const signer = await generateIdentity()
    const other = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: signer.privateKey,
      did: signer.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: other.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.AUDIENCE_MISMATCH })
  })

  it('5. wrong body is rejected', async () => {
    const id = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: JSON.stringify({ cap: 'admin' }),
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.REQUEST_MISMATCH })
  })

  it('6. wrong method is rejected', async () => {
    const id = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: 'POST',
      path: PATH,
      rawQuery: '',
      body: BODY,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: 'DELETE',
      path: PATH,
      rawQuery: '',
      body: BODY,
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.REQUEST_MISMATCH })
  })

  it('7. wrong path is rejected (URL-target-swap replay class)', async () => {
    const id = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: 'DELETE',
      path: '/spaces/A/invite-tokens/T1',
      rawQuery: '',
      body: '',
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: 'DELETE',
      path: '/spaces/A/invite-tokens/T2',
      rawQuery: '',
      body: '',
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.REQUEST_MISMATCH })
  })

  it('8. wrong query is rejected', async () => {
    const id = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: 'ttl=3600',
      body: BODY,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: 'ttl=7200',
      body: BODY,
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.REQUEST_MISMATCH })
  })

  it('9. wrong signing key is rejected', async () => {
    const claimed = await generateIdentity()
    const attacker = await generateIdentity()

    const header = await createSignedAuthHeader({
      privateKey: attacker.privateKey,
      did: claimed.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: claimed.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.SIGNATURE_INVALID })
  })

  it('10. out-of-window future timestamp is rejected', async () => {
    const id = await generateIdentity()
    const future = Date.now() + 30 * 60_000
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
      now: future,
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.FUTURE_TIMESTAMP })
  })
})
