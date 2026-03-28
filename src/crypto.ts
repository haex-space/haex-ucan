import type { SignFn, VerifyFn } from './types'

/**
 * Create an Ed25519 signing function from a CryptoKey private key.
 */
export function createWebCryptoSigner(privateKey: CryptoKey): SignFn {
  return async (data: Uint8Array): Promise<Uint8Array> => {
    const signature = await crypto.subtle.sign('Ed25519', privateKey, data as Uint8Array<ArrayBuffer>)
    return new Uint8Array(signature)
  }
}

/**
 * Create an Ed25519 verification function using WebCrypto.
 */
export function createWebCryptoVerifier(): VerifyFn {
  return async (publicKeyBytes: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> => {
    const key = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes as Uint8Array<ArrayBuffer>,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    return crypto.subtle.verify('Ed25519', key, signature as Uint8Array<ArrayBuffer>, data as Uint8Array<ArrayBuffer>)
  }
}
