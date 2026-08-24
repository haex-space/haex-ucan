export type {
  PopPayload,
  PopVerifyResult,
  PopErrorMessage,
  SignedAuthAdditionalPayload,
} from './types'
export {
  POP_HEADER_NAME,
  POP_ERROR_MESSAGES,
} from './types'

export { computeRequestHash } from './requestHash'

export {
  DEFAULT_POP_TTL_MS,
  DEFAULT_POP_CLOCK_SKEW_MS,
  createSignedAuthHeader,
  verifySignedAuthHeader,
  verifySignedAuthHeaderWithKey,
  parseSignedAuthHeaderPayload,
} from './signedAuthHeader'
export type {
  CreateSignedAuthHeaderOptions,
  VerifySignedAuthHeaderOptions,
  VerifySignedAuthHeaderWithKeyOptions,
} from './signedAuthHeader'

export {
  createUcanPopHeader,
  verifyUcanPop,
} from './ucanPop'
export type {
  CreateUcanPopHeaderOptions,
  VerifyUcanPopOptions,
} from './ucanPop'

export { fetchWithUcanPop } from './fetchWithPop'
export type { PrivateKeyResolver } from './fetchWithPop'

export { createJtiTtlCache } from './jtiCache'
export type { JtiCache, JtiCacheOptions } from './jtiCache'
