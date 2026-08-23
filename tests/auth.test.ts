import { describe, expect, it } from 'vitest'
import {
  base58btcEncode,
  computeRequestHash,
  createJtiTtlCache,
  createSignedAuthHeader,
  DEFAULT_POP_TTL_MS,
  parseSignedAuthHeaderPayload,
  POP_ERROR_MESSAGES,
  verifySignedAuthHeader,
  verifySignedAuthHeaderWithKey,
} from '../src'

interface TestIdentity {
  did: string
  privateKey: CryptoKey
  publicKey: Uint8Array
}

async function generateIdentity(): Promise<TestIdentity> {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))
  const multicodec = new Uint8Array(2 + rawPub.length)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(rawPub, 2)
  const did = `did:key:z${base58btcEncode(multicodec)}`
  return { did, privateKey: kp.privateKey, publicKey: rawPub }
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

  it('signs protocol claims without allowing PoP-field overrides', async () => {
    const id = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
      additionalPayload: { spaceId: 'space-1' },
    })

    expect(parseSignedAuthHeaderPayload(header)).toMatchObject({ did: id.did, spaceId: 'space-1' })

    const result = await verifySignedAuthHeaderWithKey({
      headerValue: header,
      expectedDid: id.did,
      publicKey: id.publicKey,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })
    expect(result.ok).toBe(true)
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
    const jtiCache = createJtiTtlCache({ sweepIntervalMs: 60_000 })
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

  it('11. future-dated proof (within skew) cannot replay before its own exp', async () => {
    // Regression: previously the jti cache used a cache-wide TTL keyed off
    // `insertedAt`. A proof timestamped `+skew` in the future has
    // `exp = timestamp + ttl = server_now + ttl + skew`, so it stayed valid
    // for `ttl + skew` from server-clock — but the jti entry evicted after
    // just `ttl` from insertion, opening a `skew`-wide replay window. The
    // cache's `has()` uses wall-clock `Date.now()` for lazy eviction, so the
    // test anchors simulated verifier timestamps to `Date.now()` — the entry
    // must still be alive relative to real time when the replay is attempted.
    const id = await generateIdentity()
    const jtiCache = createJtiTtlCache({ sweepIntervalMs: 3_600_000 })
    try {
      const t0 = Date.now()
      const clockSkewMs = 30_000
      const clientNow = t0 + clockSkewMs // signed at max future drift
      const ttlMs = 60_000

      const header = await createSignedAuthHeader({
        privateKey: id.privateKey,
        did: id.did,
        method: METHOD,
        path: PATH,
        rawQuery: RAW_QUERY,
        body: BODY,
        now: clientNow,
        ttlMs,
      })

      const first = await verifySignedAuthHeader({
        headerValue: header,
        expectedDid: id.did,
        method: METHOD,
        path: PATH,
        rawQuery: RAW_QUERY,
        body: BODY,
        now: t0,
        seenJtis: jtiCache,
        clockSkewMs,
        maxLifetimeMs: ttlMs + clockSkewMs,
      })
      expect(first.ok).toBe(true)

      // Simulated server-clock advances past a naive `insertedAt + cacheTtl`
      // window (t0 + 60_000) but the accepted proof's `exp` is clientNow +
      // ttl = t0 + 90_000. Replay must still be rejected. Wall clock during
      // this test only advances a few ms, so the cache's `has()` eviction
      // guard (against real Date.now()) still finds the entry.
      const replayAt = t0 + 70_000
      const replay = await verifySignedAuthHeader({
        headerValue: header,
        expectedDid: id.did,
        method: METHOD,
        path: PATH,
        rawQuery: RAW_QUERY,
        body: BODY,
        now: replayAt,
        seenJtis: jtiCache,
        clockSkewMs,
        maxLifetimeMs: ttlMs + clockSkewMs,
      })
      expect(replay).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.REPLAY })
    }
    finally {
      jtiCache.destroy()
    }
  })

  it('12. overlong declared lifetime is rejected', async () => {
    const id = await generateIdentity()
    const header = await createSignedAuthHeader({
      privateKey: id.privateKey,
      did: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
      ttlMs: 10 * 60_000, // 10 minutes — way over default 60s cap
    })

    const result = await verifySignedAuthHeader({
      headerValue: header,
      expectedDid: id.did,
      method: METHOD,
      path: PATH,
      rawQuery: RAW_QUERY,
      body: BODY,
    })

    expect(result).toEqual({ ok: false, reason: POP_ERROR_MESSAGES.LIFETIME_EXCEEDED })
  })
})
