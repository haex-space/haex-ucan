import type {
  EncodedUcan,
  VerifiedUcan,
  VerifyFn,
  ValidationContext,
  ValidationResult,
  Capability,
} from './types'
import { decodeUcan, getSigningInput } from './token'
import { capabilitiesSatisfy, parseSpaceResource } from './capabilities'
import { base58btcDecode } from './multibase'

/** Maximum delegation chain depth to prevent abuse */
const MAX_PROOF_DEPTH = 10

/**
 * Resolve a DID to its raw Ed25519 public key bytes (32 bytes).
 *
 * Supports did:key with Ed25519 multicodec prefix [0xed, 0x01].
 */
export function didToPublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Unsupported DID method: ${did} (only did:key supported)`)
  }

  const multicodecBytes = base58btcDecode(did.slice('did:key:z'.length))

  if (multicodecBytes[0] !== 0xed || multicodecBytes[1] !== 0x01) {
    throw new Error('Unsupported key type in did:key (expected Ed25519)')
  }

  const rawKey = multicodecBytes.slice(2)
  if (rawKey.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: ${rawKey.length}`)
  }

  return rawKey
}

/**
 * Verify a UCAN token: check signature, expiry, and recursively verify proof chain.
 *
 * @param token - Encoded UCAN token
 * @param verify - Ed25519 signature verification function
 * @param depth - Current recursion depth (internal)
 * @returns Verified UCAN with decoded proof chain
 */
export async function verifyUcan(
  token: EncodedUcan,
  verify: VerifyFn,
  depth = 0,
): Promise<VerifiedUcan> {
  if (depth > MAX_PROOF_DEPTH) {
    throw new Error(`UCAN proof chain exceeds maximum depth of ${MAX_PROOF_DEPTH}`)
  }

  const decoded = decodeUcan(token)
  const { payload, signature } = decoded

  // 1. Verify Ed25519 signature
  const issuerPublicKey = didToPublicKey(payload.iss)
  const signingInput = getSigningInput(token)
  const signatureValid = await verify(issuerPublicKey, signature, signingInput)
  if (!signatureValid) {
    throw new Error(`Invalid signature for UCAN issued by ${payload.iss}`)
  }

  // 2. Recursively verify proofs
  const verifiedProofs: VerifiedUcan[] = []
  for (const proofToken of payload.prf) {
    const verifiedProof = await verifyUcan(proofToken, verify, depth + 1)
    verifiedProofs.push(verifiedProof)
  }

  // 3. Verify delegation chain (unless root UCAN)
  if (payload.prf.length > 0) {
    verifyDelegationChain(payload.iss, payload.cap, verifiedProofs)
  }

  return {
    payload,
    proofs: verifiedProofs,
    raw: token,
  }
}

/**
 * Verify that the issuer has the right to delegate the claimed capabilities.
 *
 * Rules:
 * - At least one proof must have `aud` matching the current `iss` (chain is linked)
 * - The proof must grant a capability that satisfies each delegated capability (attenuation)
 */
function verifyDelegationChain(
  issuer: string,
  capabilities: Record<string, Capability>,
  proofs: VerifiedUcan[],
): void {
  for (const [resource, requiredCapability] of Object.entries(capabilities)) {
    let authorized = false

    for (const proof of proofs) {
      // Chain link: proof.aud must match current issuer
      if (proof.payload.aud !== issuer) continue

      if (requiredCapability === 'server/relay') {
        // server/relay can be delegated by anyone who holds any space capability
        // on the target space. The relay inherits the delegator's permission level —
        // it cannot do more than the delegating user could do directly.
        const spaceId = parseSpaceResource(resource)
        if (spaceId) {
          const spaceRes = `space:${spaceId}`
          const proofCap = proof.payload.cap[spaceRes]
          if (proofCap && proofCap.startsWith('space/')) {
            authorized = true
            break
          }
        }
      } else {
        // Attenuation: proof must grant sufficient capability for this resource
        if (capabilitiesSatisfy(proof.payload.cap, resource, requiredCapability)) {
          authorized = true
          break
        }
      }
    }

    if (!authorized) {
      throw new Error(
        `Issuer ${issuer} is not authorized to delegate ${requiredCapability} on ${resource}`
      )
    }
  }
}

/**
 * Fully validate a UCAN for a specific action.
 *
 * Performs all checks:
 * 1. Cryptographic signature verification (recursive)
 * 2. Expiry check
 * 3. Delegation chain verification (attenuation)
 * 4. Required capability check
 * 5. MLS membership check (if context provided)
 */
export async function validateUcan(
  token: EncodedUcan,
  resource: string,
  requiredCapability: Capability,
  verify: VerifyFn,
  context?: ValidationContext,
): Promise<ValidationResult> {
  const now = context?.now ?? Math.floor(Date.now() / 1000)

  try {
    // 1. Verify signature + delegation chain
    const verified = await verifyUcan(token, verify)

    // 2. Check expiry
    if (verified.payload.exp <= now) {
      return { valid: false, error: 'UCAN has expired' }
    }

    // 3. Check not-before (iat)
    if (verified.payload.iat > now + 30) {
      return { valid: false, error: 'UCAN issued in the future' }
    }

    // 4. Check required capability
    if (!capabilitiesSatisfy(verified.payload.cap, resource, requiredCapability)) {
      return {
        valid: false,
        error: `UCAN does not grant ${requiredCapability} on ${resource}`,
      }
    }

    // 5. MLS membership check (application-specific)
    if (context?.isMlsMember) {
      const spaceId = parseSpaceResource(resource)
      if (spaceId) {
        const isMember = await context.isMlsMember(verified.payload.aud, spaceId)
        if (!isMember) {
          return {
            valid: false,
            error: `${verified.payload.aud} is not an MLS member of space ${spaceId}`,
          }
        }
      }
    }

    return { valid: true }
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : 'UCAN validation failed',
    }
  }
}

/**
 * Find the root issuer (admin) of a UCAN chain.
 * Follows proofs until a root UCAN (no proofs) is found.
 */
export function findRootIssuer(verified: VerifiedUcan): string {
  if (verified.proofs.length === 0) {
    return verified.payload.iss
  }
  return findRootIssuer(verified.proofs[0]!)
}

