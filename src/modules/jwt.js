import { createHmac, timingSafeEqual } from 'node:crypto'

// Base64URL encoding (no padding)
function base64urlEncode(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function base64urlDecode(str) {
    let s = str.replace(/-/g, '+').replace(/_/g, '/')
    while (s.length % 4) s += '='
    return Buffer.from(s, 'base64')
}

// RFC 7519 section 2: a NumericDate is a JSON number. JSON.parse reads 1e999 as Infinity, which must not mean "never expires".
function isNumericDate(value) {
    return typeof value === 'number' && Number.isFinite(value)
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
        // iat is rounded down, so exp is rounded up: a fractional expiresIn must not produce an already-expired token.
        claims.exp = now + Math.ceil(options.expiresIn)
    }
    for (const claim of ['exp', 'nbf']) {
        if (claims[claim] !== undefined && !isNumericDate(claims[claim])) {
            throw new TypeError(`${claim} must be a finite number`)
        }
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

    // Not floored, so that a non-integer exp or nbf is compared at its real precision.
    const now = Date.now() / 1000

    // RFC 7519 section 4.1.4: the current time MUST be before exp.
    if (Object.hasOwn(payload, 'exp')) {
        if (!isNumericDate(payload.exp)) throw new Error('Invalid token payload')
        if (now >= payload.exp) throw new Error('Token expired')
    }

    // RFC 7519 section 4.1.5: the current time MUST be at or after nbf.
    if (Object.hasOwn(payload, 'nbf')) {
        if (!isNumericDate(payload.nbf)) throw new Error('Invalid token payload')
        if (now < payload.nbf) throw new Error('Token not yet valid')
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
