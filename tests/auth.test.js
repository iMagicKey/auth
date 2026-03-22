import { describe, it } from 'node:test'
import { expect } from 'chai'

import { sign, verify, decode, generateApiKey, hashApiKey, validateApiKey, hasPermission, hasAnyPermission } from '../src/index.js'

const SECRET = 'test-secret-key'

// ─── JWT ──────────────────────────────────────────────────────────────────────

describe('sign / verify', () => {
    it('round-trip returns correct payload fields', () => {
        const token = sign({ userId: 1, role: 'admin' }, SECRET)
        const payload = verify(token, SECRET)
        expect(payload.userId).to.equal(1)
        expect(payload.role).to.equal('admin')
    })

    it('sign adds iat claim', () => {
        const before = Math.floor(Date.now() / 1000)
        const token = sign({ x: 1 }, SECRET)
        const after = Math.floor(Date.now() / 1000)
        const { payload } = decode(token)
        expect(payload.iat).to.be.at.least(before).and.at.most(after)
    })

    it('sign with expiresIn sets exp claim', () => {
        const token = sign({ x: 1 }, SECRET, { expiresIn: 3600 })
        const { payload } = decode(token)
        expect(payload.exp).to.be.a('number')
        expect(payload.exp - payload.iat).to.equal(3600)
    })

    it('expired token throws "Token expired"', () => {
        const token = sign({ x: 1 }, SECRET, { expiresIn: -1 })
        expect(() => verify(token, SECRET)).to.throw('Token expired')
    })

    it('tampered signature throws "Invalid signature"', () => {
        const token = sign({ x: 1 }, SECRET)
        const parts = token.split('.')
        parts[2] = parts[2].split('').reverse().join('')
        expect(() => verify(parts.join('.'), SECRET)).to.throw('Invalid signature')
    })

    it('wrong number of parts throws "Invalid token format"', () => {
        expect(() => verify('a.b', SECRET)).to.throw('Invalid token format')
        expect(() => verify('a', SECRET)).to.throw('Invalid token format')
    })

    it('verify with wrong secret throws "Invalid signature"', () => {
        const token = sign({ x: 1 }, SECRET)
        expect(() => verify(token, 'wrong-secret')).to.throw('Invalid signature')
    })

    it('sign throws TypeError for invalid secret', () => {
        expect(() => sign({ x: 1 }, '')).to.throw(TypeError)
        expect(() => sign({ x: 1 }, null)).to.throw(TypeError)
        expect(() => sign({ x: 1 }, 123)).to.throw(TypeError)
    })

    it('sign throws TypeError for non-object payload', () => {
        expect(() => sign('string', SECRET)).to.throw(TypeError)
        expect(() => sign(null, SECRET)).to.throw(TypeError)
        expect(() => sign(42, SECRET)).to.throw(TypeError)
    })

    it('verify throws TypeError for non-string token', () => {
        expect(() => verify(123, SECRET)).to.throw(TypeError)
        expect(() => verify(null, SECRET)).to.throw(TypeError)
    })

    it('verify throws TypeError for invalid secret', () => {
        expect(() => verify('a.b.c', '')).to.throw(TypeError)
        expect(() => verify('a.b.c', null)).to.throw(TypeError)
    })
})

describe('decode', () => {
    it('returns header and payload without verifying signature', () => {
        const token = sign({ userId: 99 }, SECRET)
        const { header, payload } = decode(token)
        expect(header.alg).to.equal('HS256')
        expect(header.typ).to.equal('JWT')
        expect(payload.userId).to.equal(99)
    })

    it('does not throw on expired token', () => {
        const token = sign({ x: 1 }, SECRET, { expiresIn: -1 })
        expect(() => decode(token)).to.not.throw()
        const { payload } = decode(token)
        expect(payload.exp).to.be.a('number')
    })

    it('throws TypeError for non-string token', () => {
        expect(() => decode(null)).to.throw(TypeError)
        expect(() => decode(42)).to.throw(TypeError)
    })

    it('throws on invalid token format', () => {
        expect(() => decode('onlyone')).to.throw('Invalid token format')
        expect(() => decode('a.b')).to.throw('Invalid token format')
    })
})

// ─── API Keys ─────────────────────────────────────────────────────────────────

describe('generateApiKey', () => {
    it('returns a hex string of 64 characters for default length (32 bytes)', () => {
        const key = generateApiKey()
        expect(key).to.be.a('string')
        expect(key).to.have.lengthOf(64)
        expect(key).to.match(/^[a-f0-9]+$/)
    })

    it('respects custom length option', () => {
        const key = generateApiKey({ length: 16 })
        expect(key).to.have.lengthOf(32)
    })

    it('includes prefix when provided', () => {
        const key = generateApiKey({ prefix: 'sk' })
        expect(key.startsWith('sk_')).to.equal(true)
        // sk_ + 64 hex chars
        expect(key).to.have.lengthOf(67)
    })

    it('returns different values on each call', () => {
        const k1 = generateApiKey()
        const k2 = generateApiKey()
        expect(k1).to.not.equal(k2)
    })
})

describe('hashApiKey', () => {
    it('returns a 64-character hex hash', () => {
        const hash = hashApiKey('mykey', SECRET)
        expect(hash).to.be.a('string')
        expect(hash).to.have.lengthOf(64)
        expect(hash).to.match(/^[a-f0-9]+$/)
    })

    it('returns consistent hash for the same inputs', () => {
        const h1 = hashApiKey('mykey', SECRET)
        const h2 = hashApiKey('mykey', SECRET)
        expect(h1).to.equal(h2)
    })

    it('returns different hash for different key', () => {
        const h1 = hashApiKey('key1', SECRET)
        const h2 = hashApiKey('key2', SECRET)
        expect(h1).to.not.equal(h2)
    })

    it('throws TypeError for empty key', () => {
        expect(() => hashApiKey('', SECRET)).to.throw(TypeError)
        expect(() => hashApiKey(null, SECRET)).to.throw(TypeError)
    })

    it('throws TypeError for empty secret', () => {
        expect(() => hashApiKey('mykey', '')).to.throw(TypeError)
        expect(() => hashApiKey('mykey', null)).to.throw(TypeError)
    })
})

describe('validateApiKey', () => {
    it('returns true for matching key and secret', () => {
        const key = generateApiKey()
        const hash = hashApiKey(key, SECRET)
        expect(validateApiKey(key, hash, SECRET)).to.equal(true)
    })

    it('returns false for wrong key', () => {
        const key = generateApiKey()
        const hash = hashApiKey(key, SECRET)
        expect(validateApiKey('wrong-key', hash, SECRET)).to.equal(false)
    })

    it('returns false for wrong secret', () => {
        const key = generateApiKey()
        const hash = hashApiKey(key, SECRET)
        expect(validateApiKey(key, hash, 'wrong-secret')).to.equal(false)
    })

    it('returns false for empty key', () => {
        const key = generateApiKey()
        const hash = hashApiKey(key, SECRET)
        expect(validateApiKey('', hash, SECRET)).to.equal(false)
    })

    it('returns false when storedHash is invalid hex', () => {
        const key = generateApiKey()
        expect(validateApiKey(key, 'not-a-valid-hash', SECRET)).to.equal(false)
    })
})

// ─── Permissions ─────────────────────────────────────────────────────────────

describe('hasPermission', () => {
    it('returns true when all required permissions are present', () => {
        expect(hasPermission(['users:read', 'posts:write'], ['users:read', 'posts:write'])).to.equal(true)
    })

    it('returns false when one required permission is missing', () => {
        expect(hasPermission(['users:read'], ['users:read', 'posts:write'])).to.equal(false)
    })

    it('returns true with wildcard "*"', () => {
        expect(hasPermission(['*'], 'anything:delete')).to.equal(true)
    })

    it('accepts single string as required', () => {
        expect(hasPermission(['users:read'], 'users:read')).to.equal(true)
        expect(hasPermission(['users:read'], 'users:write')).to.equal(false)
    })

    it('returns false for empty userPermissions array', () => {
        expect(hasPermission([], 'users:read')).to.equal(false)
    })

    it('returns false for non-array userPermissions', () => {
        expect(hasPermission(null, 'users:read')).to.equal(false)
        expect(hasPermission('users:read', 'users:read')).to.equal(false)
        expect(hasPermission(undefined, 'users:read')).to.equal(false)
    })

    it('returns true when required array is empty (vacuously true)', () => {
        expect(hasPermission(['users:read'], [])).to.equal(true)
    })
})

describe('hasAnyPermission', () => {
    it('returns true when at least one permission matches', () => {
        expect(hasAnyPermission(['users:read', 'posts:write'], ['users:delete', 'posts:write'])).to.equal(true)
    })

    it('returns false when none of the permissions match', () => {
        expect(hasAnyPermission(['users:read'], ['users:write', 'posts:delete'])).to.equal(false)
    })

    it('returns true with wildcard "*"', () => {
        expect(hasAnyPermission(['*'], ['users:delete', 'posts:write'])).to.equal(true)
    })

    it('accepts single string as required', () => {
        expect(hasAnyPermission(['users:read'], 'users:read')).to.equal(true)
        expect(hasAnyPermission(['users:read'], 'posts:write')).to.equal(false)
    })

    it('returns false for empty userPermissions array', () => {
        expect(hasAnyPermission([], ['users:read', 'posts:write'])).to.equal(false)
    })

    it('returns false for non-array userPermissions', () => {
        expect(hasAnyPermission(null, 'users:read')).to.equal(false)
        expect(hasAnyPermission(undefined, ['users:read'])).to.equal(false)
    })
})
