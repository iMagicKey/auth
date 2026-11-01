import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { sign, verify } from '../src/index.js'
import { SECRET } from './craftToken.js'

const T = 1_800_000_000 // an arbitrary whole second, used as the mocked clock reading
const EXPIRES_IN = 60

class Document {
    constructor() {
        this.sub = 'u1'
    }

    get exp() {
        return 1
    }

    toJSON() {
        return { sub: this.sub }
    }
}

class Plainish {
    sub = 'u1'
}

function setClock(t) {
    t.mock.timers.enable({ apis: ['Date'], now: T * 1000 })
}

/** The claims sign promises to add must be in the signed token, whatever else the payload holds. */
function assertIssuedClaims(payload) {
    const claims = verify(sign(payload, SECRET, { expiresIn: EXPIRES_IN }), SECRET)
    assert.equal(claims.iat, T)
    assert.equal(claims.exp, T + EXPIRES_IN)
    return claims
}

describe('sign: rejects payloads whose serialized form could lose claims', () => {
    const REJECTED = {
        'an own toJSON that replaces the claims': { toJSON: () => ({ sub: 1 }) },
        'an own toJSON method on an otherwise plain object': {
            sub: 'u1',
            toJSON() {
                return { sub: 1 }
            },
        },
        'an own toJSON returning a non-object': { toJSON: () => 1 },
        'an own toJSON returning undefined': { toJSON: () => undefined },
        'an own toJSON getter returning a function': {
            get toJSON() {
                return () => ({ sub: 1 })
            },
        },
        'a null-prototype object with own toJSON': Object.assign(Object.create(null), { toJSON: () => ({ sub: 1 }) }),
        'a class instance with toJSON (an ORM document)': new Document(),
        'a class instance without toJSON': new Plainish(),
        'a Date': new Date(0),
        'a Map': new Map([[1, 2]]),
        'a Set': new Set([1]),
        'a RegExp': /x/,
        'an Error': new Error('x'),
        'a Buffer': Buffer.from('x'),
        'an array': [1, 2],
        'an empty array': [],
        'a String object': new String('x'),
        'an object inheriting claims': Object.create({ exp: 1 }),
    }

    for (const [label, payload] of Object.entries(REJECTED)) {
        it(`throws TypeError for ${label}, with or without expiresIn`, () => {
            assert.throws(() => sign(payload, SECRET), TypeError)
            assert.throws(() => sign(payload, SECRET, { expiresIn: EXPIRES_IN }), TypeError)
        })
    }

    it('throws TypeError for a toJSON inherited from a polluted Object.prototype', () => {
        Object.prototype.toJSON = () => ({ sub: 1 })
        try {
            assert.throws(() => sign({ sub: 'u1' }, SECRET, { expiresIn: EXPIRES_IN }), TypeError)
        } finally {
            delete Object.prototype.toJSON
        }
    })
})

describe('sign: the serialized claims include iat and exp', () => {
    it('for a plain object', (t) => {
        setClock(t)
        assert.equal(assertIssuedClaims({ sub: 'u1' }).sub, 'u1')
    })

    it('for an empty object', (t) => {
        setClock(t)
        assertIssuedClaims({})
    })

    it('for a null-prototype object', (t) => {
        setClock(t)
        assert.equal(assertIssuedClaims(Object.assign(Object.create(null), { sub: 'u1' })).sub, 'u1')
    })

    it('for an object from JSON.parse with an own __proto__ key', (t) => {
        setClock(t)
        assertIssuedClaims(JSON.parse('{"__proto__":{"exp":1}}'))
    })

    it('for an explicit copy of a class instance, the documented migration', (t) => {
        setClock(t)
        assert.equal(assertIssuedClaims({ ...new Document() }).sub, 'u1')
    })

    it('when a nested value has toJSON, which only affects that value', (t) => {
        setClock(t)
        const claims = assertIssuedClaims({ at: new Date(0), nested: { toJSON: () => 'n' } })
        assert.equal(claims.at, '1970-01-01T00:00:00.000Z')
        assert.equal(claims.nested, 'n')
    })

    it('when toJSON is a non-function value, which JSON.stringify keeps as data', (t) => {
        setClock(t)
        assert.equal(assertIssuedClaims({ toJSON: 'data' }).toJSON, 'data')
    })

    it('reads an own toJSON getter once, so it cannot pass the check and then replace the claims', (t) => {
        setClock(t)
        let reads = 0
        const payload = {
            get toJSON() {
                reads += 1
                return reads > 1 ? () => ({ sub: 1 }) : undefined
            },
        }
        assertIssuedClaims(payload)
        assert.equal(reads, 1)
    })

    it('iat is present without expiresIn, and exp stays absent', (t) => {
        setClock(t)
        const claims = verify(sign({ sub: 'u1' }, SECRET), SECRET)
        assert.equal(claims.iat, T)
        assert.equal(Object.hasOwn(claims, 'exp'), false)
    })

    it('expiresIn replaces a caller-supplied exp, and iat replaces a caller-supplied iat', (t) => {
        setClock(t)
        assertIssuedClaims({ exp: 1, iat: 1 })
    })
})
