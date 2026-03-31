import { describe, it, expect, beforeAll } from 'vitest'
import {
  createUcan,
  decodeUcan,
  verifyUcan,
  validateUcan,
  satisfies,
  canDelegate,
  spaceResource,
  serverResource,
  createWebCryptoSigner,
  createWebCryptoVerifier,
  findRootIssuer,
} from '../src'
import type { EncodedUcan, SignFn } from '../src'

// ── Test helpers ─────────────────────────────────────────────────────

interface TestIdentity {
  did: string
  publicKey: Uint8Array
  privateKey: CryptoKey
  sign: SignFn
}

async function generateTestIdentity(): Promise<TestIdentity> {
  const keypair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair

  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keypair.publicKey))

  // Encode as did:key (Ed25519 multicodec: [0xed, 0x01] + 32 bytes)
  const multicodec = new Uint8Array(2 + rawPublicKey.length)
  multicodec[0] = 0xed
  multicodec[1] = 0x01
  multicodec.set(rawPublicKey, 2)
  const did = `did:key:z${base58btcEncode(multicodec)}`

  return {
    did,
    publicKey: rawPublicKey,
    privateKey: keypair.privateKey,
    sign: createWebCryptoSigner(keypair.privateKey),
  }
}

const verify = createWebCryptoVerifier()
const SPACE_ID = 'test-space-123'
const ONE_HOUR = 3600
const futureExp = () => Math.floor(Date.now() / 1000) + ONE_HOUR

// ── Capability tests ─────────────────────────────────────────────────

describe('capabilities', () => {
  it('admin satisfies all space capabilities', () => {
    expect(satisfies('space/admin', 'space/admin')).toBe(true)
    expect(satisfies('space/admin', 'space/invite')).toBe(true)
    expect(satisfies('space/admin', 'space/write')).toBe(true)
    expect(satisfies('space/admin', 'space/read')).toBe(true)
  })

  it('write does not satisfy admin or invite', () => {
    expect(satisfies('space/write', 'space/admin')).toBe(false)
    expect(satisfies('space/write', 'space/invite')).toBe(false)
  })

  it('read only satisfies read', () => {
    expect(satisfies('space/read', 'space/read')).toBe(true)
    expect(satisfies('space/read', 'space/write')).toBe(false)
  })

  it('server/relay only satisfies itself', () => {
    expect(satisfies('server/relay', 'server/relay')).toBe(true)
    expect(satisfies('server/relay', 'space/read')).toBe(false)
    expect(satisfies('space/admin', 'server/relay')).toBe(false)
  })

  it('canDelegate follows same rules as satisfies', () => {
    expect(canDelegate('space/admin', 'space/write')).toBe(true)
    expect(canDelegate('space/write', 'space/admin')).toBe(false)
    expect(canDelegate('space/read', 'space/read')).toBe(true)
  })
})

// ── Token encoding/decoding ──────────────────────────────────────────

describe('token encoding', () => {
  it('should create and decode a root UCAN', async () => {
    const admin = await generateTestIdentity()

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource(SPACE_ID)]: 'space/admin' },
      expiration: futureExp(),
    }, admin.sign)

    const decoded = decodeUcan(token)

    expect(decoded.header.alg).toBe('EdDSA')
    expect(decoded.header.typ).toBe('JWT')
    expect(decoded.payload.ucv).toBe('1.0')
    expect(decoded.payload.iss).toBe(admin.did)
    expect(decoded.payload.aud).toBe(admin.did)
    expect(decoded.payload.cap[spaceResource(SPACE_ID)]).toBe('space/admin')
    expect(decoded.payload.prf).toEqual([])
    expect(decoded.payload.nnc).toBeTruthy()
  })

  it('should reject invalid tokens', () => {
    expect(() => decodeUcan('not-a-token')).toThrow()
    expect(() => decodeUcan('a.b')).toThrow('expected 3')
  })
})

// ── Signature verification ───────────────────────────────────────────

describe('signature verification', () => {
  it('should verify a validly signed UCAN', async () => {
    const admin = await generateTestIdentity()

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource(SPACE_ID)]: 'space/admin' },
      expiration: futureExp(),
    }, admin.sign)

    const verified = await verifyUcan(token, verify)
    expect(verified.payload.iss).toBe(admin.did)
  })

  it('should reject a tampered token', async () => {
    const admin = await generateTestIdentity()

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource(SPACE_ID)]: 'space/admin' },
      expiration: futureExp(),
    }, admin.sign)

    // Tamper with payload
    const parts = token.split('.')
    const tampered = `${parts[0]}.${parts[1]}x.${parts[2]}`

    await expect(verifyUcan(tampered, verify)).rejects.toThrow()
  })

  it('should reject a token signed with wrong key', async () => {
    const admin = await generateTestIdentity()
    const attacker = await generateTestIdentity()

    // Token claims to be from admin but signed by attacker
    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [spaceResource(SPACE_ID)]: 'space/admin' },
      expiration: futureExp(),
    }, attacker.sign)

    await expect(verifyUcan(token, verify)).rejects.toThrow('Invalid signature')
  })
})

// ── Delegation chain ─────────────────────────────────────────────────

describe('delegation chain', () => {
  it('should verify admin → owner → member chain', async () => {
    const admin = await generateTestIdentity()
    const owner = await generateTestIdentity()
    const member = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    // Admin creates root UCAN (self-signed)
    const rootUcan = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [resource]: 'space/admin' },
      expiration: futureExp(),
    }, admin.sign)

    // Admin delegates to owner
    const ownerUcan = await createUcan({
      issuer: admin.did,
      audience: owner.did,
      capabilities: { [resource]: 'space/invite' },
      proofs: [rootUcan],
      expiration: futureExp(),
    }, admin.sign)

    // Owner delegates to member
    const memberUcan = await createUcan({
      issuer: owner.did,
      audience: member.did,
      capabilities: { [resource]: 'space/write' },
      proofs: [ownerUcan],
      expiration: futureExp(),
    }, owner.sign)

    // Verify the full chain
    const verified = await verifyUcan(memberUcan, verify)
    expect(verified.payload.aud).toBe(member.did)
    expect(verified.proofs.length).toBe(1)
    expect(verified.proofs[0]!.proofs.length).toBe(1)

    // Find root issuer
    expect(findRootIssuer(verified)).toBe(admin.did)
  })

  it('should reject privilege escalation (attenuation violation)', async () => {
    const admin = await generateTestIdentity()
    const member = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    // Admin gives member space/write
    const memberUcan = await createUcan({
      issuer: admin.did,
      audience: member.did,
      capabilities: { [resource]: 'space/write' },
      expiration: futureExp(),
    }, admin.sign)

    // Member tries to delegate space/admin (privilege escalation!)
    const escalatedUcan = await createUcan({
      issuer: member.did,
      audience: (await generateTestIdentity()).did,
      capabilities: { [resource]: 'space/admin' },
      proofs: [memberUcan],
      expiration: futureExp(),
    }, member.sign)

    await expect(verifyUcan(escalatedUcan, verify)).rejects.toThrow('not authorized')
  })

  it('should reject broken chain (audience mismatch)', async () => {
    const admin = await generateTestIdentity()
    const owner = await generateTestIdentity()
    const stranger = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    // Admin delegates to owner
    const ownerUcan = await createUcan({
      issuer: admin.did,
      audience: owner.did,
      capabilities: { [resource]: 'space/invite' },
      expiration: futureExp(),
    }, admin.sign)

    // Stranger tries to use owner's UCAN as proof (but aud doesn't match stranger)
    const badUcan = await createUcan({
      issuer: stranger.did,
      audience: (await generateTestIdentity()).did,
      capabilities: { [resource]: 'space/write' },
      proofs: [ownerUcan],
      expiration: futureExp(),
    }, stranger.sign)

    await expect(verifyUcan(badUcan, verify)).rejects.toThrow('not authorized')
  })
})

// ── Full validation ──────────────────────────────────────────────────

describe('validateUcan', () => {
  it('should validate a complete token with required capability', async () => {
    const admin = await generateTestIdentity()
    const member = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    const memberUcan = await createUcan({
      issuer: admin.did,
      audience: member.did,
      capabilities: { [resource]: 'space/write' },
      expiration: futureExp(),
    }, admin.sign)

    const result = await validateUcan(memberUcan, resource, 'space/write', verify)
    expect(result.valid).toBe(true)
  })

  it('should reject expired token', async () => {
    const admin = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    const token = await createUcan({
      issuer: admin.did,
      audience: admin.did,
      capabilities: { [resource]: 'space/admin' },
      expiration: Math.floor(Date.now() / 1000) - 100, // Expired 100 seconds ago
    }, admin.sign)

    const result = await validateUcan(token, resource, 'space/admin', verify)
    expect(result.valid).toBe(false)
    expect(result.error).toContain('expired')
  })

  it('should reject insufficient capability', async () => {
    const admin = await generateTestIdentity()
    const reader = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    const readerUcan = await createUcan({
      issuer: admin.did,
      audience: reader.did,
      capabilities: { [resource]: 'space/read' },
      expiration: futureExp(),
    }, admin.sign)

    const result = await validateUcan(readerUcan, resource, 'space/write', verify)
    expect(result.valid).toBe(false)
    expect(result.error).toContain('does not grant')
  })

  it('should check MLS membership when context provided', async () => {
    const admin = await generateTestIdentity()
    const member = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    const memberUcan = await createUcan({
      issuer: admin.did,
      audience: member.did,
      capabilities: { [resource]: 'space/write' },
      expiration: futureExp(),
    }, admin.sign)

    // Member is NOT in MLS group
    const result = await validateUcan(memberUcan, resource, 'space/write', verify, {
      isMlsMember: async () => false,
    })
    expect(result.valid).toBe(false)
    expect(result.error).toContain('not an MLS member')
  })

  it('should pass when MLS membership confirmed', async () => {
    const admin = await generateTestIdentity()
    const member = await generateTestIdentity()
    const resource = spaceResource(SPACE_ID)

    const memberUcan = await createUcan({
      issuer: admin.did,
      audience: member.did,
      capabilities: { [resource]: 'space/write' },
      expiration: futureExp(),
    }, admin.sign)

    const result = await validateUcan(memberUcan, resource, 'space/write', verify, {
      isMlsMember: async () => true,
    })
    expect(result.valid).toBe(true)
  })
})

// ── Server delegation ────────────────────────────────────────────────

describe('server delegation', () => {
  it('should create and verify server/relay delegation', async () => {
    const admin = await generateTestIdentity()
    const user = await generateTestIdentity()
    const serverDid = 'did:web:sync.example.com'
    const resource = spaceResource(SPACE_ID)

    // Admin gives user space/write
    const userUcan = await createUcan({
      issuer: admin.did,
      audience: user.did,
      capabilities: { [resource]: 'space/write' },
      expiration: futureExp(),
    }, admin.sign)

    // User delegates server/relay to their server (scoped to space)
    const serverUcan = await createUcan({
      issuer: user.did,
      audience: serverDid,
      capabilities: { [resource]: 'server/relay' },
      proofs: [userUcan],
      expiration: futureExp(),
    }, user.sign)

    const verified = await verifyUcan(serverUcan, verify)
    expect(verified.payload.aud).toBe(serverDid)
    expect(verified.payload.cap[resource]).toBe('server/relay')
  })
})

// ── Base58-btc encode (for test identity generation) ─────────────────

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0
  for (const b of bytes) {
    if (b !== 0) break
    zeros++
  }
  const digits: number[] = []
  for (const b of bytes) {
    let carry = b
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  return '1'.repeat(zeros) + digits.reverse().map(d => BASE58_ALPHABET[d]).join('')
}
