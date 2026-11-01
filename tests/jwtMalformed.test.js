import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { sign, verify, decode } from '../src/index.js'
import { SECRET, HS256_HEADER, craftToken, craftRawToken, encodeSegment } from './craftToken.js'

const invalidFormat = { message: 'Invalid token format' }
const invalidSignature = { message: 'Invalid signature' }
const invalidPayload = { message: 'Invalid token payload' }

const HEADER = encodeSegment(HS256_HEADER)
const PAYLOAD = encodeSegment({ sub: 'u1' })
const MAX_TOKEN_LENGTH = 1024 * 1024

/** A failure must be a plain documented Error, not a stray TypeError, RangeError or SyntaxError. */
function assertPlainError(fn, message) {
    assert.throws(fn, (err) => {
        assert.equal(err.constructor, Error)
        assert.equal(err.message, message)
        return true
    })
}

describe('verify: non-object payload (RFC 7519 section 7.2)', () => {
    const NON_OBJECTS = {
        array: '[]',
        'array of claims': '[{"sub":"u1"}]',
        number: '42',
        zero: '0',
        string: '"sub"',
        'empty string': '""',
        null: 'null',
        true: 'true',
        false: 'false',
    }

    for (const [label, json] of Object.entries(NON_OBJECTS)) {
        it(`rejects a ${label} payload despite a valid HMAC`, () => {
            assertPlainError(() => verify(craftToken(json), SECRET), 'Invalid token payload')
        })
    }

    it('rejects a payload that is not JSON', () => {
        assertPlainError(() => verify(craftToken('{ not json'), SECRET), 'Invalid token payload')
    })

    it('rejects a deeply nested array payload without an unexpected error type', () => {
        const depth = 100_000
        assertPlainError(() => verify(craftToken('['.repeat(depth) + ']'.repeat(depth)), SECRET), 'Invalid token payload')
    })

    it('accepts an empty object payload', () => {
        assert.deepEqual(verify(craftToken({}), SECRET), {})
    })
})

describe('verify: __proto__ in the payload', () => {
    const POLLUTING = '{"sub":"u1","__proto__":{"admin":true,"exp":1},"constructor":{"prototype":{"admin":true}}}'

    it('does not change the prototype of the returned object', () => {
        const payload = verify(craftToken(POLLUTING), SECRET)
        assert.equal(Object.getPrototypeOf(payload), Object.prototype)
        assert.equal(payload.admin, undefined)
    })

    it('does not pollute Object.prototype', () => {
        verify(craftToken(POLLUTING), SECRET)
        assert.equal({}.admin, undefined)
    })

    it('does not read exp through __proto__', () => {
        assert.equal(verify(craftToken('{"__proto__":{"exp":1}}'), SECRET).exp, undefined)
    })

    it('keeps the signed __proto__ key as ordinary data through a sign and verify round trip', () => {
        const signed = sign(JSON.parse('{"__proto__":{"admin":true}}'), SECRET)
        const payload = verify(signed, SECRET)
        assert.equal(Object.getPrototypeOf(payload), Object.prototype)
        assert.equal(payload.admin, undefined)
    })
})

describe('verify: token structure', () => {
    for (const token of ['', '.', '..', '...', 'a', 'a.b', 'a.b.c.d', `${HEADER}.${PAYLOAD}`, `${HEADER}.${PAYLOAD}.sig.extra`]) {
        it(`rejects ${JSON.stringify(token.slice(0, 12))}, length ${token.length}, with an invalid format or signature error`, () => {
            assert.throws(() => verify(token, SECRET), (err) => err.constructor === Error && /^Invalid (token format|signature)$/.test(err.message))
        })
    }

    it('rejects empty segments with a genuine HMAC', () => {
        assertPlainError(() => verify(craftRawToken('', PAYLOAD), SECRET), 'Invalid token format')
        assertPlainError(() => verify(craftRawToken(HEADER, ''), SECRET), 'Invalid token format')
    })

    it('rejects an empty signature', () => {
        assertPlainError(() => verify(`${HEADER}.${PAYLOAD}.`, SECRET), 'Invalid token format')
    })

    it('rejects a token made only of dots', () => {
        const token = '.'.repeat(MAX_TOKEN_LENGTH)
        assertPlainError(() => verify(token, SECRET), 'Invalid token format')
    })
})

describe('verify: segments must be base64url (RFC 7515 section 5.2)', () => {
    const toBase64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64')
    const MALFORMED = {
        'an illegal character': (s) => `${s}!`,
        'embedded whitespace': (s) => `${s.slice(0, 4)} ${s.slice(4)}`,
        'a trailing newline': (s) => `${s}\n`,
        'non-ASCII text': (s) => `${s}é`,
        'padding': (s) => `${s}${'='.repeat(4 - (s.length % 4 || 4)) || '===='}`,
    }

    for (const [label, mutate] of Object.entries(MALFORMED)) {
        it(`rejects a header containing ${label}, despite a genuine HMAC`, () => {
            assertPlainError(() => verify(craftRawToken(mutate(HEADER), PAYLOAD), SECRET), 'Invalid token format')
        })

        it(`rejects a payload containing ${label}, despite a genuine HMAC`, () => {
            assertPlainError(() => verify(craftRawToken(HEADER, mutate(PAYLOAD)), SECRET), 'Invalid token format')
        })
    }

    it('rejects standard base64 characters that base64url excludes', () => {
        const payload = toBase64({ a: '>>>???' })
        assert.match(payload, /[+/]/)
        assertPlainError(() => verify(craftRawToken(HEADER, payload), SECRET), 'Invalid token format')
    })

    it('rejects a segment with an impossible base64 length', () => {
        const oneTooMany = PAYLOAD + 'A'.repeat((1 - (PAYLOAD.length % 4) + 4) % 4)
        assert.equal(oneTooMany.length % 4, 1)
        assertPlainError(() => verify(craftRawToken(HEADER, oneTooMany), SECRET), 'Invalid token format')
    })

    it('rejects a signature with an illegal character', () => {
        const [header, payload, signature] = sign({}, SECRET).split('.')
        assertPlainError(() => verify(`${header}.${payload}.${signature.slice(0, -1)}!`, SECRET), 'Invalid token format')
    })

    it('rejects a padded copy of a valid signature', () => {
        assertPlainError(() => verify(`${sign({}, SECRET)}=`, SECRET), 'Invalid token format')
    })
})

describe('verify: oversized tokens', () => {
    const tokenOfLength = (length) => {
        const signingOverhead = craftToken({ d: '' }).length
        return craftToken({ d: 'x'.repeat(Math.floor((length - signingOverhead) * 0.75)) })
    }

    it('rejects an oversized genuine token as an invalid format', () => {
        assertPlainError(() => verify(tokenOfLength(MAX_TOKEN_LENGTH + 1024), SECRET), 'Invalid token format')
    })

    it('rejects one oversized segment as an invalid format', () => {
        assertPlainError(() => verify(`${HEADER}.${'A'.repeat(MAX_TOKEN_LENGTH)}.sig`, SECRET), 'Invalid token format')
    })

    it('accepts a large token under the limit', () => {
        assert.equal(typeof verify(tokenOfLength(MAX_TOKEN_LENGTH - 1024), SECRET).d, 'string')
    })

    it('sign refuses to issue a token that verify would reject', () => {
        assert.throws(() => sign({ d: 'x'.repeat(MAX_TOKEN_LENGTH) }, SECRET), TypeError)
    })

    it('sign still issues a large token that verify accepts', () => {
        const payload = { d: 'x'.repeat(Math.floor(MAX_TOKEN_LENGTH * 0.7)) }
        assert.equal(verify(sign(payload, SECRET), SECRET).d, payload.d)
    })
})

describe('verify: the HMAC check still rejects tampering', () => {
    const flipChar = (segment, index) => {
        const replacement = segment[index] === 'A' ? 'B' : 'A'
        return `${segment.slice(0, index)}${replacement}${segment.slice(index + 1)}`
    }

    it('rejects a changed payload that keeps the original signature', () => {
        const [header, , signature] = sign({ role: 'user' }, SECRET).split('.')
        const forged = encodeSegment({ role: 'admin', iat: 1 })
        assertPlainError(() => verify(`${header}.${forged}.${signature}`, SECRET), 'Invalid signature')
    })

    it('rejects a changed header that keeps the original signature', () => {
        const [, payload, signature] = sign({ role: 'user' }, SECRET).split('.')
        const forged = encodeSegment({ alg: 'HS256', typ: 'JWT', kid: 'x' })
        assertPlainError(() => verify(`${forged}.${payload}.${signature}`, SECRET), 'Invalid signature')
    })

    it('rejects a single changed character in every position of every segment', () => {
        const parts = sign({ role: 'user' }, SECRET).split('.')
        parts.forEach((segment, segmentIndex) => {
            for (let i = 0; i < segment.length; i += 1) {
                const tampered = parts.map((part, j) => (j === segmentIndex ? flipChar(part, i) : part)).join('.')
                assert.throws(() => verify(tampered, SECRET), invalidSignature, `segment ${segmentIndex}, position ${i}`)
            }
        })
    })

    it('rejects a truncated signature', () => {
        const token = sign({}, SECRET)
        assertPlainError(() => verify(token.slice(0, -4), SECRET), 'Invalid signature')
    })

    it('rejects an extended signature', () => {
        assertPlainError(() => verify(`${sign({}, SECRET)}AAAA`, SECRET), 'Invalid signature')
    })

    it('rejects a token signed with a different secret', () => {
        assertPlainError(() => verify(craftToken({ sub: 'u1' }, { secret: 'another-synthetic-secret' }), SECRET), 'Invalid signature')
    })

    it('rejects a signature taken from another valid token', () => {
        const [headerA, payloadA] = sign({ sub: 'a' }, SECRET).split('.')
        const signatureB = sign({ sub: 'b' }, SECRET).split('.')[2]
        assertPlainError(() => verify(`${headerA}.${payloadA}.${signatureB}`, SECRET), 'Invalid signature')
    })

    it('reports a bad payload only after the signature passes', () => {
        const token = `${HEADER}.${encodeSegment('[]')}.${'A'.repeat(43)}`
        assert.throws(() => verify(token, SECRET), invalidSignature)
        assert.throws(() => verify(craftToken('[]'), SECRET), invalidPayload)
    })
})

describe('verify: argument types are unchanged', () => {
    it('throws TypeError for a non-string token', () => {
        for (const token of [undefined, null, 1, {}, [], Buffer.from('a.b.c')]) {
            assert.throws(() => verify(token, SECRET), TypeError)
        }
    })

    it('rejects a malformed token as invalid format, never with an unexpected type', () => {
        assert.throws(() => verify('!!!.???.***', SECRET), invalidFormat)
    })
})

describe('decode: malformed base64url', () => {
    it('throws an invalid format error when segments do not decode to JSON', () => {
        assertPlainError(() => decode('!!!.???.***'), 'Invalid token format')
        assertPlainError(() => decode('..'), 'Invalid token format')
    })
})
