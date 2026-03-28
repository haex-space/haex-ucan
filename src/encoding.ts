/**
 * Base64url encode (RFC 4648 §5, no padding)
 */
export function base64urlEncode(data: Uint8Array): string {
  const binString = Array.from(data, (byte) => String.fromCodePoint(byte)).join('')
  return btoa(binString)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/**
 * Base64url decode (RFC 4648 §5)
 */
export function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const binString = atob(padded)
  return Uint8Array.from(binString, (c) => c.codePointAt(0)!)
}

/**
 * Encode an object as a Base64url JSON string
 */
export function encodeJsonBase64url(obj: unknown): string {
  const json = JSON.stringify(obj)
  return base64urlEncode(new TextEncoder().encode(json))
}

/**
 * Decode a Base64url JSON string to an object
 */
export function decodeJsonBase64url<T>(str: string): T {
  const bytes = base64urlDecode(str)
  const json = new TextDecoder().decode(bytes)
  return JSON.parse(json) as T
}
