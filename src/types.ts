/**
 * UCAN Token Header (JWS)
 */
export interface UcanHeader {
  alg: 'EdDSA'
  typ: 'JWT'
}

/**
 * Space capability levels, ordered from most to least privileged.
 *
 * Attenuation rule: a capability can only delegate equal or lower levels.
 *   admin  → can delegate: admin, invite, write, read
 *   invite → can delegate: invite, write, read
 *   write  → can delegate: write, read
 *   read   → can delegate: read
 */
export type SpaceCapability = 'space/admin' | 'space/invite' | 'space/write' | 'space/read'

export const SpaceCapabilities = {
  ADMIN: 'space/admin',
  INVITE: 'space/invite',
  WRITE: 'space/write',
  READ: 'space/read',
} as const satisfies Record<string, SpaceCapability>

/**
 * Server delegation capability — allows a server to relay MLS messages
 * on behalf of a user.
 */
export type ServerCapability = 'server/relay'

export const ServerCapabilities = {
  RELAY: 'server/relay',
} as const satisfies Record<string, ServerCapability>

export type Capability = SpaceCapability | ServerCapability

/**
 * DID-Auth action identifiers.
 * Used in DID-Auth signed requests to specify what operation is being authorized.
 * These are NOT UCAN capabilities — they identify the intent of a signed request
 * where no UCAN is required (e.g., space creation, vault key operations).
 */
export enum DidAuthAction {
  // Sync operations
  SyncPush = 'sync-push',
  SyncPull = 'sync-pull',
  SyncPullColumns = 'sync-pull-columns',

  // Vault key operations
  VaultKeyUpload = 'vault-key-upload',
  VaultKeyGet = 'vault-key-get',
  VaultKeyUpdate = 'vault-key-update',
  VaultDelete = 'vault-delete',
  VaultDeleteAll = 'vault-delete-all',
  VaultList = 'vault-list',

  // Space operations
  CreateSpace = 'create-space',
  ListSpaces = 'list-spaces',
  AcceptInvite = 'accept-invite',
  DeclineInvite = 'decline-invite',
  SelfLeave = 'self-leave',

  // Identity operations
  UpdateRecovery = 'update-recovery',
  StorageCredentials = 'storage-credentials',

  // WebSocket
  WsConnect = 'ws-connect',
}

/**
 * Capabilities map: resource identifier → capability level
 *
 * Resource identifiers:
 *   - "space:<space-id>" for space capabilities
 *   - "server:<server-did>" for server delegation
 */
export type Capabilities = Record<string, Capability>

/**
 * Additional facts attached to the token.
 * Used for MLS epoch binding and other metadata.
 */
export interface UcanFacts {
  /** MLS epoch from which this token is valid */
  validFromEpoch?: number
  /** Any additional application-specific facts */
  [key: string]: unknown
}

/**
 * UCAN Token Payload
 */
export interface UcanPayload {
  /** UCAN version */
  ucv: '1.0'
  /** Issuer DID (who created this token) */
  iss: string
  /** Audience DID (who this token is for) */
  aud: string
  /** Capabilities granted */
  cap: Capabilities
  /** Additional facts (e.g. MLS epoch binding) */
  fct?: UcanFacts
  /** Expiration (Unix timestamp in seconds) */
  exp: number
  /** Issued at (Unix timestamp in seconds) */
  iat: number
  /** Nonce for uniqueness */
  nnc?: string
  /** Proofs — Base64url-encoded parent UCANs that authorize this delegation */
  prf: string[]
}

/**
 * A complete encoded UCAN token (header.payload.signature)
 */
export type EncodedUcan = string

/**
 * A decoded and parsed UCAN (before signature verification)
 */
export interface DecodedUcan {
  header: UcanHeader
  payload: UcanPayload
  signature: Uint8Array
  raw: EncodedUcan
}

/**
 * A fully verified UCAN with its decoded proof chain
 */
export interface VerifiedUcan {
  payload: UcanPayload
  proofs: VerifiedUcan[]
  raw: EncodedUcan
}

/**
 * Authenticated UCAN context — set by middleware after successful verification.
 * Generic enough for any server/client using UCAN auth.
 */
export interface UcanContext {
  /** Issuer DID from the verified UCAN */
  issuerDid: string
  /** Public key identifier (typically same as issuer DID) */
  publicKey: string
  /** Capabilities granted by the UCAN */
  capabilities: Capabilities
  /** The full verified UCAN for further inspection */
  verifiedUcan: VerifiedUcan
}

/**
 * Signing function interface — abstracts over WebCrypto, Tauri commands, etc.
 * Takes raw bytes, returns Ed25519 signature bytes.
 */
export type SignFn = (data: Uint8Array) => Promise<Uint8Array>

/**
 * Verification function interface — abstracts over WebCrypto, Tauri commands, etc.
 * Takes public key bytes, signature bytes, and data bytes.
 * Returns true if signature is valid.
 */
export type VerifyFn = (publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array) => Promise<boolean>

/**
 * Parameters for creating a new UCAN token
 */
export interface CreateUcanParams {
  issuer: string
  audience: string
  capabilities: Capabilities
  /** Proofs (encoded parent UCANs) that authorize this delegation */
  proofs?: EncodedUcan[]
  /** Expiration as Unix timestamp in seconds, or duration in seconds from now */
  expiration: number
  /** Additional facts */
  facts?: UcanFacts
  /** Nonce (auto-generated if not provided) */
  nonce?: string
}

/**
 * Validation context — provides the external state needed for full verification.
 * The UCAN library handles cryptographic and structural checks;
 * the caller provides application-specific state (e.g. MLS membership).
 */
export interface ValidationContext {
  /** Check if a DID is a current MLS group member for a given space */
  isMlsMember?: (did: string, spaceId: string) => Promise<boolean>
  /** Current Unix timestamp in seconds (defaults to Date.now()/1000) */
  now?: number
}

/**
 * Result of a validation attempt
 */
export interface ValidationResult {
  valid: boolean
  error?: string
}
