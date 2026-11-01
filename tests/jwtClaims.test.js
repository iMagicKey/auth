import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { sign, verify, decode } from '../src/index.js'
import { SECRET, craftToken } from './craftToken.js'

const T = 1_800_000_000 // an arbitrary whole second, used as the mocked clock reading

function setClock(t, seconds) {
    t.mock.timers.enable({ apis: ['Date'], now: Math.round(seconds * 1000) })
}

const expired = { message: 'Token expired' }
const notYetValid = { message: 'Token not yet valid' }
const invalidPayload = { message: 'Invalid token payload' }

// JSON text is used for 1e999 because JSON.parse reads it as Infinity, and JSON.stringify cannot produce it.
const NON_NUMERIC_CLAIMS = {
    string: '"9999999999"',
    'non-numeric string': '"never"',
    'empty string': '""',
    null: 'null',
    object: '{}',
    array: '[9999999999]',
    'boolean true': 'true',
    'boolean false': 'false',
    'Infinity via 1e999': '1e999',
    '-Infinity via -1e999': '-1e999',
}

describe('verify: exp (RFC 7519 section 4.1.4)', () => {
    it('accepts one second before exp', (t) => {
        setClock(t, T - 1)
        assert.equal(verify(craftToken({ exp: T }), SECRET).exp, T)
    })

    it('accepts one millisecond before exp', (t) => {
        setClock(t, T - 0.001)
        assert.equal(verify(craftToken({ exp: T }), SECRET).exp, T)
    })

    it('rejects at exactly exp', (t) => {
        setClock(t, T)
        assert.throws(() => verify(craftToken({ exp: T }), SECRET), expired)
    })

    it('rejects one second after exp', (t) => {
        setClock(t, T + 1)
        assert.throws(() => verify(craftToken({ exp: T }), SECRET), expired)
    })

    it('rejects exp of 0 and negative exp as expired', (t) => {
        setClock(t, T)
        assert.throws(() => verify(craftToken({ exp: 0 }), SECRET), expired)
        assert.throws(() => verify(craftToken({ exp: -1 }), SECRET), expired)
    })

    it('honours the fractional part of a non-integer exp', (t) => {
        const token = craftToken({ exp: T + 0.5 })
        setClock(t, T + 0.4)
        assert.equal(verify(token, SECRET).exp, T + 0.5)
        t.mock.timers.setTime((T + 0.6) * 1000)
        assert.throws(() => verify(token, SECRET), expired)
    })

    it('accepts a token with no exp claim', (t) => {
        setClock(t, T)
        assert.deepEqual(verify(craftToken({ sub: 'u1' }), SECRET), { sub: 'u1' })
    })

    for (const [label, json] of Object.entries(NON_NUMERIC_CLAIMS)) {
        it(`rejects exp as ${label} instead of treating it as never-expiring`, (t) => {
            setClock(t, T)
            assert.throws(() => verify(craftToken(`{"sub":"u1","exp":${json}}`), SECRET), invalidPayload)
        })
    }
})

describe('verify: nbf (RFC 7519 section 4.1.5)', () => {
    it('rejects one second before nbf', (t) => {
        setClock(t, T - 1)
        assert.throws(() => verify(craftToken({ nbf: T }), SECRET), notYetValid)
    })

    it('rejects one millisecond before nbf', (t) => {
        setClock(t, T - 0.001)
        assert.throws(() => verify(craftToken({ nbf: T }), SECRET), notYetValid)
    })

    it('accepts at exactly nbf', (t) => {
        setClock(t, T)
        assert.equal(verify(craftToken({ nbf: T }), SECRET).nbf, T)
    })

    it('accepts after nbf', (t) => {
        setClock(t, T + 1)
        assert.equal(verify(craftToken({ nbf: T }), SECRET).nbf, T)
    })

    it('accepts nbf of 0', (t) => {
        setClock(t, T)
        assert.equal(verify(craftToken({ nbf: 0 }), SECRET).nbf, 0)
    })

    it('honours the fractional part of a non-integer nbf', (t) => {
        const token = craftToken({ nbf: T + 0.5 })
        setClock(t, T + 0.4)
        assert.throws(() => verify(token, SECRET), notYetValid)
        t.mock.timers.setTime((T + 0.6) * 1000)
        assert.equal(verify(token, SECRET).nbf, T + 0.5)
    })

    it('enforces both claims together', (t) => {
        const token = craftToken({ nbf: T, exp: T + 10 })
        setClock(t, T - 1)
        assert.throws(() => verify(token, SECRET), notYetValid)
        t.mock.timers.setTime(T * 1000)
        assert.equal(verify(token, SECRET).exp, T + 10)
        t.mock.timers.setTime((T + 10) * 1000)
        assert.throws(() => verify(token, SECRET), expired)
    })

    for (const [label, json] of Object.entries(NON_NUMERIC_CLAIMS)) {
        it(`rejects nbf as ${label}`, (t) => {
            setClock(t, T)
            assert.throws(() => verify(craftToken(`{"sub":"u1","nbf":${json}}`), SECRET), invalidPayload)
        })
    }
})

describe('sign: only issues time claims that verify accepts', () => {
    it('a token is verifiable at the instant it is signed, for any expiresIn and clock phase', (t) => {
        setClock(t, T)
        for (const phase of [0, 0.001, 0.5, 0.7, 0.999]) {
            for (const expiresIn of [0.001, 0.5, 0.9, 1, 1.5, 3600]) {
                t.mock.timers.setTime(Math.round((T + phase) * 1000))
                const token = sign({ sub: 'u1' }, SECRET, { expiresIn })
                assert.equal(verify(token, SECRET).sub, 'u1', `phase ${phase}, expiresIn ${expiresIn}`)
            }
        }
    })

    it('a fractional expiresIn produces a whole-second exp', (t) => {
        setClock(t, T + 0.7)
        const { payload } = decode(sign({}, SECRET, { expiresIn: 0.5 }))
        assert.equal(payload.exp, T + 1)
    })

    it('a token with an integer expiresIn expires exactly at iat + expiresIn', (t) => {
        setClock(t, T + 0.7)
        const token = sign({}, SECRET, { expiresIn: 10 })
        const { payload } = decode(token)
        assert.equal(payload.iat, T)
        assert.equal(payload.exp, T + 10)
        t.mock.timers.setTime((T + 10) * 1000 - 1)
        assert.equal(verify(token, SECRET).exp, T + 10)
        t.mock.timers.setTime((T + 10) * 1000)
        assert.throws(() => verify(token, SECRET), expired)
    })

    for (const claim of ['exp', 'nbf']) {
        for (const value of ['never', null, {}, true, NaN, Infinity, -Infinity]) {
            it(`throws TypeError for payload.${claim} = ${typeof value === 'object' ? JSON.stringify(value) : String(value)}`, () => {
                assert.throws(() => sign({ [claim]: value }, SECRET), TypeError)
            })
        }

        it(`keeps a valid numeric payload.${claim}`, (t) => {
            setClock(t, T)
            assert.equal(decode(sign({ [claim]: T + 5 }, SECRET)).payload[claim], T + 5)
        })

        it(`treats payload.${claim} = undefined as absent`, (t) => {
            setClock(t, T)
            const token = sign({ [claim]: undefined }, SECRET)
            assert.equal(Object.hasOwn(verify(token, SECRET), claim), false)
        })
    }

    it('expiresIn replaces an invalid payload.exp', (t) => {
        setClock(t, T)
        assert.equal(verify(sign({ exp: 'never' }, SECRET, { expiresIn: 10 }), SECRET).exp, T + 10)
    })
})
