import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto'

/**
 * Generates a cryptographically secure API key.
 * @param {object} options - { length: 32, prefix: '' }
 * @returns {string} hex-encoded API key (optionally prefixed)
 */
export function generateApiKey(options = {}) {
    const length = options.length ?? 32
    const prefix = options.prefix ?? ''
    const key = randomBytes(length).toString('hex')
    return prefix ? `${prefix}_${key}` : key
}

/**
 * Hashes an API key for safe storage (HMAC-SHA256).
 * @param {string} key
 * @param {string} secret - server-side secret for HMAC
 * @returns {string} hex hash
 */
export function hashApiKey(key, secret) {
    if (!key || typeof key !== 'string') throw new TypeError('key must be a non-empty string')
    if (!secret || typeof secret !== 'string') throw new TypeError('secret must be a non-empty string')
    return createHmac('sha256', secret).update(key).digest('hex')
}

/**
 * Validates an API key against its stored hash using timing-safe comparison.
 * @param {string} key - the provided key
 * @param {string} storedHash - the hash stored in DB
 * @param {string} secret - server-side HMAC secret
 * @returns {boolean}
 */
export function validateApiKey(key, storedHash, secret) {
    try {
        const expectedHash = hashApiKey(key, secret)
        const a = Buffer.from(expectedHash, 'hex')
        const b = Buffer.from(storedHash, 'hex')
        if (a.length !== b.length) return false
        return timingSafeEqual(a, b)
    } catch {
        return false
    }
}
