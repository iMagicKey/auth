import { createHmac } from 'node:crypto'

export const SECRET = 'synthetic-test-secret'
export const HS256_HEADER = { alg: 'HS256', typ: 'JWT' }

export const encodeSegment = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url')

export const signingSignature = (signingInput, secret = SECRET) => createHmac('sha256', secret).update(signingInput).digest('base64url')

/**
 * Builds a token with a genuine HMAC over arbitrary content, independently of the library's sign().
 * Strings are embedded verbatim as the segment's JSON text; anything else is JSON-serialized.
 */
export function craftToken(payload, { header = HS256_HEADER, secret = SECRET } = {}) {
    const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`
    return `${signingInput}.${signingSignature(signingInput, secret)}`
}

/** Builds a token with a genuine HMAC over already-encoded segments, which may be malformed. */
export function craftRawToken(headerSegment, payloadSegment, secret = SECRET) {
    const signingInput = `${headerSegment}.${payloadSegment}`
    return `${signingInput}.${signingSignature(signingInput, secret)}`
}
