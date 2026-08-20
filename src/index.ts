export type {
  UcanHeader,
  UcanPayload,
  UcanFacts,
  CapabilityValue,
  Capabilities,
  ServerCapability,
  EncodedUcan,
  DecodedUcan,
  VerifiedUcan,
  UcanContext,
  SignFn,
  VerifyFn,
  CreateUcanParams,
  ValidationContext,
  ValidationResult,
} from './types'

export type {
  SpaceCap,
  CapEntry,
  SpaceCapabilitySet,
  SpaceCapabilitySetBuilder,
  SpaceRole,
  DelegationError,
  DelegationErrorKind,
  ServerCap,
} from './capabilities'

export type { RequiredCapability } from './verify'

export { DidAuthAction, SpaceCaps, ServerCapabilities } from './types'

export { createUcan, decodeUcan, getSigningInput } from './token'
export { verifyUcan, validateUcan, findRootIssuer, didToPublicKey } from './verify'
export {
  spaceCapabilitySet,
  spaceCapabilitySetFromEntries,
  spaceRolePreset,
  SPACE_ROLES,
  holdsSpaceCap,
  isSpaceCapDelegatable,
  enforceDelegatable,
  isSpaceCapValue,
  isServerCapValue,
  holdsServerCap,
  SPACE_CAP_ORDER,
  parseSpaceResource,
  spaceResource,
  serverResource,
} from './capabilities'
export { createWebCryptoSigner, createWebCryptoVerifier } from './crypto'
export { base64urlEncode, base64urlDecode } from './encoding'
export {
  base58btcEncode,
  base58btcDecode,
  multibaseEncode,
  multibaseDecode,
  publicKeyToDid,
  didToRawPublicKey,
} from './multibase'
