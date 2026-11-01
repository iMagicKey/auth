import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { sign, verify, decode } from '../src/index.js'
import { SECRET, craftToken, craftRawToken, encodeSegment } from './craftToken.js'

const invalidHeader = { message: 'Invalid token header' }
const PAYLOAD = { sub: 'u1' }

// Every token below carries a genuine HMAC, so only the header check can reject it.
describe('verify: alg must equal the algorithm used to verify (RFC 8725 section 3.1)', () => {
    const REJECTED_HEADERS = {
        'alg none': { alg: 'none', typ: 'JWT' },
        'alg None': { alg: 'None' },
        'alg NONE': { alg: 'NONE' },
        'alg RS256': { alg: 'RS256' },
        'alg HS512': { alg: 'HS512' },
        'alg hs256 (case differs)': { alg: 'hs256' },
        'alg with surrounding space': { alg: ' HS256 ' },
        'alg empty string': { alg: '' },
        'missing alg': { typ: 'JWT' },
        'empty object': {},
        'alg null': { alg: null },
        'alg number': { alg: 256 },
        'alg true': { alg: true },
        'alg array': { alg: ['HS256'] },
        'alg object': { alg: { name: 'HS256' } },
    }

    for (const [label, header] of Object.entries(REJECTED_HEADERS)) {
        it(`rejects ${label} despite a valid HMAC`, () => {
            assert.throws(() => verify(craftToken(PAYLOAD, { header }), SECRET), invalidHeader)
        })
    }

    it('rejects alg supplied only through a __proto__ key', () => {
        assert.throws(() => verify(craftToken(PAYLOAD, { header: '{"__proto__":{"alg":"HS256"}}' }), SECRET), invalidHeader)
    })

    it('uses the last of duplicate alg members, so none cannot hide behind HS256', () => {
        assert.throws(() => verify(craftToken(PAYLOAD, { header: '{"alg":"HS256","alg":"none"}' }), SECRET), invalidHeader)
    })

    it('rejects alg none with an empty signature, the classic forgery', () => {
        const forged = `${encodeSegment({ alg: 'none' })}.${encodeSegment(PAYLOAD)}.`
        assert.throws(() => verify(forged, SECRET), Error)
    })

    it('rejects alg none with a wrong signature as an invalid signature', () => {
        const [header, payload] = craftToken(PAYLOAD, { header: { alg: 'none' } }).split('.')
        assert.throws(() => verify(`${header}.${payload}.${'A'.repeat(43)}`, SECRET), { message: 'Invalid signature' })
    })

    it('an algorithm named by the token is never used: an HS512 HMAC does not verify', async () => {
        const { createHmac } = await import('node:crypto')
        const signingInput = `${encodeSegment({ alg: 'HS512' })}.${encodeSegment(PAYLOAD)}`
        const signature = createHmac('sha512', SECRET).update(signingInput).digest('base64url')
        assert.throws(() => verify(`${signingInput}.${signature}`, SECRET), { message: 'Invalid signature' })
    })
})

describe('verify: the header must be a JSON object', () => {
    const NON_OBJECTS = { array: '["HS256"]', number: '256', string: '"HS256"', null: 'null', true: 'true' }

    for (const [label, json] of Object.entries(NON_OBJECTS)) {
        it(`rejects a ${label} header despite a valid HMAC`, () => {
            assert.throws(() => verify(craftToken(PAYLOAD, { header: json }), SECRET), invalidHeader)
        })
    }

    it('rejects a header that is not JSON despite a valid HMAC', () => {
        assert.throws(() => verify(craftRawToken(encodeSegment('not json'), encodeSegment(PAYLOAD)), SECRET), invalidHeader)
    })

    it('rejects an array header whose elements look like a valid header', () => {
        assert.throws(() => verify(craftToken(PAYLOAD, { header: '[{"alg":"HS256"}]' }), SECRET), invalidHeader)
    })
})

describe('verify: crit (RFC 7515 section 4.1.11)', () => {
    for (const crit of [['exp'], ['b64'], [], null, 'exp']) {
        it(`rejects crit = ${JSON.stringify(crit)} because no extensions are supported`, () => {
            assert.throws(() => verify(craftToken(PAYLOAD, { header: { alg: 'HS256', crit } }), SECRET), invalidHeader)
        })
    }
})

describe('verify: accepted headers', () => {
    it('accepts tokens from sign', () => {
        assert.equal(verify(sign(PAYLOAD, SECRET), SECRET).sub, 'u1')
    })

    it('accepts HS256 with no typ', () => {
        assert.equal(verify(craftToken(PAYLOAD, { header: { alg: 'HS256' } }), SECRET).sub, 'u1')
    })

    it('accepts HS256 with a different typ and unrelated parameters', () => {
        const header = { alg: 'HS256', typ: 'at+jwt', kid: 'key-1' }
        assert.equal(verify(craftToken(PAYLOAD, { header }), SECRET).sub, 'u1')
    })

    it('decode still reports a rejected header for inspection', () => {
        const token = craftToken(PAYLOAD, { header: { alg: 'none' } })
        assert.equal(decode(token).header.alg, 'none')
    })
})
