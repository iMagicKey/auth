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

// The only algorithm this library signs and verifies with. Nothing in a token can select another one.
const ALGORITHM = 'HS256'

// Far beyond what any HTTP header carries. Bounds the work verify does on untrusted input before the signature is checked.
const MAX_TOKEN_LENGTH = 1024 * 1024

// RFC 7519 section 2: a NumericDate is a JSON number. JSON.parse reads 1e999 as Infinity, which must not mean "never expires".
function isNumericDate(value) {
    return typeof value === 'number' && Number.isFinite(value)
}

// Spreading anything else into the claims silently loses data: class getters, Map and Date contents, inherited values.
function isPlainObject(value) {
    if (typeof value !== 'object' || value === null) return false
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
}

// RFC 7515 section 5.2: no padding, whitespace or other additional characters. A length of 4n + 1 is not valid base64.
function isBase64urlSegment(segment) {
    return /^[A-Za-z0-9_-]+$/.test(segment) && segment.length % 4 !== 1
}

// RFC 7519 section 7.2: the header and the claims set must both be JSON objects. Returns null for anything else.
function decodeJsonObject(segment) {
    let value
    try {
        value = JSON.parse(base64urlDecode(segment).toString('utf8'))
    } catch {
        return null
    }
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null
}

// RFC 8725 section 3.1: alg must match the algorithm used to verify. RFC 7515 section 4.1.11: crit lists extensions
// the recipient must understand, and this library supports none.
function isValidHeader(header) {
    return header !== null && Object.hasOwn(header, 'alg') && header.alg === ALGORITHM && !Object.hasOwn(header, 'crit')
}

/**
 * Signs a payload and returns a JWT string.
 * @param {object} payload - a plain object with no toJSON function
 * @param {string} secret
 * @param {object} options - { expiresIn: number (seconds) }
 * @returns {string} JWT token
 */
export function sign(payload, secret, options = {}) {
    if (!secret || typeof secret !== 'string') throw new TypeError('secret must be a non-empty string')
    if (!isPlainObject(payload)) throw new TypeError('payload must be a plain object')

    const header = { alg: ALGORITHM, typ: 'JWT' }
    const now = Math.floor(Date.now() / 1000)
    const claims = { ...payload, iat: now }
    // JSON.stringify would serialize what toJSON returns instead of these claims, dropping iat and exp. Checked on the
    // copy, so that a getter is read only once and cannot pass this check and then return a function.
    if (typeof claims.toJSON === 'function') throw new TypeError('payload must not have a toJSON function')
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

    const token = `${signingInput}.${signature}`
    if (token.length > MAX_TOKEN_LENGTH) throw new TypeError('payload is too large to produce a verifiable token')
    return token
}

/**
 * Verifies a JWT and returns the decoded payload.
 * @param {string} token
 * @param {string} secret
 * @returns {object} decoded payload
 * @throws {Error} if invalid, expired or not yet valid
 */
export function verify(token, secret) {
    if (!secret || typeof secret !== 'string') throw new TypeError('secret must be a non-empty string')
    if (typeof token !== 'string') throw new TypeError('token must be a string')

    if (token.length > MAX_TOKEN_LENGTH) throw new Error('Invalid token format')

    const parts = token.split('.', 4)
    if (parts.length !== 3 || !parts.every(isBase64urlSegment)) throw new Error('Invalid token format')

    const [headerEncoded, payloadEncoded, signatureEncoded] = parts
    const signingInput = `${headerEncoded}.${payloadEncoded}`

    const expectedSig = base64urlEncode(createHmac('sha256', secret).update(signingInput).digest())

    // Constant-time comparison
    const expectedBuf = Buffer.from(expectedSig)
    const actualBuf = Buffer.from(signatureEncoded)
    if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
        throw new Error('Invalid signature')
    }

    // The signature is checked first, so that nothing unauthenticated gets parsed.
    if (!isValidHeader(decodeJsonObject(headerEncoded))) throw new Error('Invalid token header')

    const payload = decodeJsonObject(payloadEncoded)
    if (payload === null) throw new Error('Invalid token payload')

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
