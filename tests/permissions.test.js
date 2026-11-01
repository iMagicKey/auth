import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { hasPermission, hasAnyPermission } from '../src/index.js'

const CHECKS = { hasPermission, hasAnyPermission }

const INVALID_REQUIREMENTS = {
    null: null,
    undefined,
    number: 1,
    zero: 0,
    boolean: true,
    object: {},
    'object with toString': { toString: () => 'users:read' },
    'String object': new String('users:read'),
    function: () => 'users:read',
    symbol: Symbol('users:read'),
    '[null]': [null],
    '[undefined]': [undefined],
    '[number]': [1],
    '[object]': [{}],
    '[nested array]': [['users:read']],
    '[symbol]': [Symbol('users:read')],
    'sparse array': new Array(3),
    'valid then null': ['users:read', null],
    'null then valid': [null, 'users:read'],
    'valid then hole': ['users:read', , 'users:read'], // eslint-disable-line no-sparse-arrays
}

const INVALID_PERMISSIONS = {
    null: null,
    undefined,
    string: 'users:read',
    number: 1,
    object: {},
    'array-like object': { 0: 'users:read', length: 1, includes: () => true },
    Set: new Set(['users:read']),
    '[null]': [null],
    '[undefined]': [undefined],
    '[number]': [1],
    '[object]': [{}],
    '[nested array]': [['users:read']],
    'sparse array': new Array(3),
    'valid then null': ['users:read', null],
    'null then valid': [null, 'users:read'],
    'wildcard then null': ['*', null],
    'null then wildcard': [null, '*'],
    'glob then number': ['users.*', 1],
}

for (const [name, check] of Object.entries(CHECKS)) {
    describe(`${name}: fails closed on invalid input and never throws`, () => {
        for (const [label, required] of Object.entries(INVALID_REQUIREMENTS)) {
            it(`returns false for an exact-match holder, required ${label}`, () => {
                assert.equal(check(['users:read'], required), false)
            })

            it(`returns false for a glob holder, required ${label}`, () => {
                assert.equal(check(['users.*'], required), false)
            })

            it(`returns false for a wildcard holder, required ${label}`, () => {
                assert.equal(check(['*'], required), false)
            })
        }

        for (const [label, permissions] of Object.entries(INVALID_PERMISSIONS)) {
            it(`returns false for permissions ${label}`, () => {
                assert.equal(check(permissions, 'users:read'), false)
                assert.equal(check(permissions, ['users:read']), false)
            })
        }

        it('returns false when both arguments are invalid', () => {
            assert.equal(check(null, null), false)
            assert.equal(check([null], [null]), false)
        })
    })

    describe(`${name}: prototype-related names are ordinary strings`, () => {
        const NAMES = ['constructor', '__proto__', 'prototype', 'toString', 'hasOwnProperty', 'length', 'includes']

        for (const perm of NAMES) {
            it(`does not grant "${perm}" to an unrelated holder`, () => {
                assert.equal(check(['users:read'], perm), false)
                assert.equal(check(['users.*'], perm), false)
                assert.equal(check([], perm), false)
            })

            it(`does not grant anything to a holder of "${perm}"`, () => {
                assert.equal(check([perm], 'users:read'), false)
                assert.equal(check([`${perm}.*`], 'users.read'), false)
            })

            it(`grants "${perm}" only as an exact match, a glob or the wildcard`, () => {
                assert.equal(check([perm], perm), true)
                assert.equal(check([`${perm}.*`], `${perm}.child`), true)
                assert.equal(check(['*'], perm), true)
            })
        }

        it('does not pollute Object.prototype', () => {
            check(['__proto__.*'], '__proto__.polluted')
            assert.equal({}.polluted, undefined)
        })
    })

    describe(`${name}: valid input is unchanged`, () => {
        it('the wildcard grants any string requirement', () => {
            assert.equal(check(['*'], 'users:read'), true)
            assert.equal(check(['*'], ['users:read', 'posts:write']), true)
            assert.equal(check(['users:read', '*'], 'posts:write'), true)
        })

        it('an empty permission list holds nothing', () => {
            assert.equal(check([], 'users:read'), false)
        })

        it('a glob matches its prefix and children only', () => {
            assert.equal(check(['users.*'], 'users'), true)
            assert.equal(check(['users.*'], 'users.read'), true)
            assert.equal(check(['users.*'], 'usersx.read'), false)
        })

        it('comparison is case-sensitive', () => {
            assert.equal(check(['Users:Read'], 'users:read'), false)
        })
    })
}

// Empty requirements are not defined by README.md or AGENT.md. These pin the current results, which the owner may
// change: audit finding AU-04 notes that hasPermission(perms, []) fails open for a computed empty requirement.
describe('empty requirement list: current behaviour, pending an owner decision', () => {
    it('hasPermission returns true (vacuously)', () => {
        assert.equal(hasPermission(['users:read'], []), true)
        assert.equal(hasPermission([], []), true)
        assert.equal(hasPermission(['*'], []), true)
    })

    it('hasAnyPermission returns false, except for a wildcard holder', () => {
        assert.equal(hasAnyPermission(['users:read'], []), false)
        assert.equal(hasAnyPermission([], []), false)
        assert.equal(hasAnyPermission(['*'], []), true)
    })

    it('invalid permissions still fail closed', () => {
        assert.equal(hasPermission(null, []), false)
        assert.equal(hasAnyPermission(null, []), false)
    })
})
