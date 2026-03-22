import { createHmac, timingSafeEqual } from 'node:crypto'

// Base64URL encoding (no padding)
function base64urlEncode(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/')
    while (str.length % 4) str += '='
    return Buffer.from(str, 'base64')
}

/**
 * Signs a payload and returns a JWT string.
 * @param {object} payload
 * @param {string} secret
 * @param {object} options - { expiresIn: number (seconds) }
 * @returns {string} JWT token
 */
export function sign(payload, secret, options = {}) {
    if (!secret || typeof secret !== 'string') throw new TypeError('secret must be a non-empty string')
    if (typeof payload !== 'object' || payload === null) throw new TypeError('payload must be an object')

    const header = { alg: 'HS256', typ: 'JWT' }
    const now = Math.floor(Date.now() / 1000)
    const claims = { ...payload, iat: now }
    if (options.expiresIn != null) {
        if (!Number.isFinite(options.expiresIn) || options.expiresIn <= 0) {
            throw new TypeError('expiresIn must be a positive finite number')
        }
        claims.exp = Math.floor(Date.now() / 1000) + options.expiresIn
    }

    const headerEncoded = base64urlEncode(Buffer.from(JSON.stringify(header)))
    const payloadEncoded = base64urlEncode(Buffer.from(JSON.stringify(claims)))
    const signingInput = `${headerEncoded}.${payloadEncoded}`
    const signature = base64urlEncode(createHmac('sha256', secret).update(signingInput).digest())

    return `${signingInput}.${signature}`
}

/**
 * Verifies a JWT and returns the decoded payload.
 * @param {string} token
 * @param {string} secret
 * @returns {object} decoded payload
 * @throws {Error} if invalid or expired
 */
export function verify(token, secret) {
    if (!secret || typeof secret !== 'string') throw new TypeError('secret must be a non-empty string')
    if (typeof token !== 'string') throw new TypeError('token must be a string')

    const parts = token.split('.')
    if (parts.length !== 3) throw new Error('Invalid token format')

    const [headerEncoded, payloadEncoded, signatureEncoded] = parts
    const signingInput = `${headerEncoded}.${payloadEncoded}`

    const expectedSig = base64urlEncode(createHmac('sha256', secret).update(signingInput).digest())

    // Constant-time comparison
    const expectedBuf = Buffer.from(expectedSig)
    const actualBuf = Buffer.from(signatureEncoded)
    if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
        throw new Error('Invalid signature')
    }

    let payload
    try {
        payload = JSON.parse(base64urlDecode(payloadEncoded).toString('utf8'))
    } catch {
        throw new Error('Invalid token payload')
    }

    const now = Math.floor(Date.now() / 1000)
    if (payload.exp != null && payload.exp < now) {
        throw new Error('Token expired')
    }

    return payload
}

/**
 * Decodes a JWT without verifying the signature.
 * @param {string} token
 * @returns {{ header: object, payload: object }}
 */
export function decode(token) {
    if (typeof token !== 'string') throw new TypeError('token must be a string')
    const parts = token.split('.')
    if (parts.length !== 3) throw new Error('Invalid token format')
    try {
        return {
            header: JSON.parse(base64urlDecode(parts[0]).toString('utf8')),
            payload: JSON.parse(base64urlDecode(parts[1]).toString('utf8')),
        }
    } catch {
        throw new Error('Invalid token format')
    }
}
