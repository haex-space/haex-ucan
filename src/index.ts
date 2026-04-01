export type {
  UcanHeader,
  UcanPayload,
  UcanFacts,
  SpaceCapability,
  ServerCapability,
  Capability,
  Capabilities,
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

export { DidAuthAction, SpaceCapabilities, ServerCapabilities } from './types'

export { createUcan, decodeUcan, getSigningInput } from './token'
export { verifyUcan, validateUcan, findRootIssuer, didToPublicKey } from './verify'
export {
  satisfies,
  canDelegate,
  capabilitiesSatisfy,
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
