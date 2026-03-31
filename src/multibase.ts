/**
 * Multibase base58btc encoding/decoding (z prefix).
 * Conformant with the W3C Multibase specification.
 *
 * Also provides Ed25519 DID ↔ raw key conversions using
 * the multicodec prefix 0xed01.
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

// ── Base58btc encode/decode ──────────────────────────────────────────

export function base58btcEncode(bytes: Uint8Array): string {
  const digits = [0]
  for (const byte of bytes) {
    let carry = byte
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! * 256
      digits[j] = carry % 58
      carry = Math.floor(carry / 58)
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = Math.floor(carry / 58)
    }
  }

  let result = ''
  for (const byte of bytes) {
    if (byte !== 0) break
    result += '1'
  }

  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]!]
  }

  return result
}

export function base58btcDecode(str: string): Uint8Array {
  let zeros = 0
  for (const c of str) {
    if (c !== '1') break
    zeros++
  }

  const bytes: number[] = []
  for (const c of str) {
    const value = BASE58_ALPHABET.indexOf(c)
    if (value === -1) throw new Error(`Invalid base58 character: ${c}`)
    let carry = value
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }

  const result = new Uint8Array(zeros + bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    result[zeros + i] = bytes[bytes.length - 1 - i]!
  }
  return result
}

// ── Multibase wrappers (z prefix = base58btc) ───────────────────────

export function multibaseEncode(bytes: Uint8Array): string {
  return `z${base58btcEncode(bytes)}`
}

export function multibaseDecode(encoded: string): Uint8Array {
  if (!encoded.startsWith('z')) {
    throw new Error(`Unsupported multibase prefix: '${encoded[0]}' (expected 'z' for base58btc)`)
  }
  return base58btcDecode(encoded.slice(1))
}

// ── Ed25519 DID ↔ raw key helpers ───────────────────────────────────

const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01])

/**
 * Convert a raw 32-byte Ed25519 public key to a did:key DID.
 */
export function publicKeyToDid(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${rawPublicKey.length} bytes`)
  }
  const multicodec = new Uint8Array(2 + 32)
  multicodec.set(ED25519_MULTICODEC_PREFIX)
  multicodec.set(rawPublicKey, 2)
  return `did:key:z${base58btcEncode(multicodec)}`
}

/**
 * Extract the raw 32-byte Ed25519 public key from a did:key DID.
 * Alias for the existing didToPublicKey from verify.ts.
 */
export function didToRawPublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Unsupported DID method: ${did} (only did:key supported)`)
  }
  const multicodecBytes = base58btcDecode(did.slice('did:key:z'.length))
  if (multicodecBytes[0] !== 0xed || multicodecBytes[1] !== 0x01) {
    throw new Error('Unsupported key type in did:key (expected Ed25519)')
  }
  return multicodecBytes.slice(2)
}
