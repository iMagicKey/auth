# AGENT — imagic-auth

## Purpose

Provides JWT signing/verification (HMAC-SHA256, no third-party deps), cryptographically secure API key generation/hashing/validation, and permission checking utilities for Node.js.

## Package

- npm: `imagic-auth`
- import (local): `import { sign, verify, decode, generateApiKey, hashApiKey, validateApiKey, hasPermission, hasAnyPermission } from '../src/index.js'`
- import (installed): `import { sign, verify, ... } from 'imagic-auth'`
- zero runtime deps (uses `node:crypto` built-in)

## Exports

### `sign(payload, secret, options?): string`

- `payload` {object} — plain object to embed in the token; must not be null or an array
- `secret` {string} — non-empty HMAC signing key
- `options.expiresIn` {number} [undefined] — expiry in **seconds** from now; adds `exp` claim
- returns: JWT string (`header.payload.signature`, base64url-encoded)
- throws: `TypeError` — if `secret` is not a non-empty string or `payload` is not a plain object
- always adds `iat` claim (current Unix timestamp in seconds)

### `verify(token, secret): object`

- `token` {string} — JWT string to verify
- `secret` {string} — signing secret used during `sign`
- returns: decoded payload object (includes `iat`, and `exp` if set)
- throws: `Error('Invalid token format')` — not a 3-part JWT
- throws: `Error('Invalid signature')` — HMAC mismatch
- throws: `Error('Token expired')` — current time is past `exp`
- throws: `Error('Invalid token payload')` — payload cannot be base64url-decoded or JSON-parsed

### `decode(token): { header: object, payload: object }`

- `token` {string} — JWT string (signature not verified)
- returns: `{ header, payload }` — both decoded from base64url JSON
- throws: `TypeError` — if `token` is not a string
- throws: `Error` — if the token does not have 3 parts or base64url decoding fails

### `generateApiKey(options?): string`

- `options.length` {number} [32] — byte count for `crypto.randomBytes`; output length is `length * 2` hex chars
- `options.prefix` {string} [''] — when non-empty, key is `{prefix}_{hex}`; when empty, key is just the hex string
- returns: unique key string
- throws: never under normal conditions
- each call returns a different value; there is no way to reproduce a previous key

### `hashApiKey(key, secret): string`

- `key` {string} — the raw API key to hash
- `secret` {string} — HMAC secret for hashing; keep this constant per environment
- returns: 64-character lowercase hex HMAC-SHA256 digest
- throws: `TypeError` — if `key` or `secret` is an empty string

### `validateApiKey(key, storedHash, secret): boolean`

- `key` {string} — raw key provided by the client
- `storedHash` {string} — previously stored hash from `hashApiKey`
- `secret` {string} — same secret used during `hashApiKey`
- returns: `true` if the key matches the stored hash; `false` on any mismatch or error
- throws: never — returns `false` instead of throwing on bad input

### `hasPermission(userPermissions, required): boolean`

- `userPermissions` {string[]} — array of permission strings the user holds
- `required` {string | string[]} — one or more permissions that must all be present
- returns: `true` only if **all** required permissions are in `userPermissions`
- `'*'` in `userPermissions` grants all permissions
- returns `false` if `userPermissions` is not an array
- throws: never

### `hasAnyPermission(userPermissions, required): boolean`

- `userPermissions` {string[]} — array of permission strings the user holds
- `required` {string | string[]} — one or more permissions; at least one must be present
- returns: `true` if **any** of the required permissions is in `userPermissions`
- `'*'` in `userPermissions` grants all permissions
- returns `false` if `userPermissions` is not an array
- throws: never

## Usage Patterns

### Issue and verify a JWT

```js
import { sign, verify } from '../src/index.js'

const token = sign({ userId: 42, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: 3600 })

try {
    const payload = verify(token, process.env.JWT_SECRET)
    console.log(payload.userId) // 42
} catch (err) {
    // 'Invalid signature' | 'Token expired' | 'Invalid token format'
    console.error(err.message)
}
```

### Inspect token without verifying

```js
import { decode } from '../src/index.js'

const { header, payload } = decode(token)
console.log(header.alg)    // 'HS256'
console.log(payload.exp)   // Unix timestamp or undefined
```

### Generate, store, and validate API keys

```js
import { generateApiKey, hashApiKey, validateApiKey } from '../src/index.js'

// On key creation (send raw key to user once, never store it):
const rawKey = generateApiKey({ prefix: 'sk', length: 32 })
const hash = hashApiKey(rawKey, process.env.API_KEY_SECRET)
await db.saveApiKey({ hash })

// On request authentication:
const incomingKey = req.headers['x-api-key']
const record = await db.findApiKeyByHash(/* lookup strategy */)
const valid = validateApiKey(incomingKey, record.hash, process.env.API_KEY_SECRET)
if (!valid) throw new UnauthorizedError('Invalid API key')
```

### Permission checks in route handlers

```js
import { hasPermission, hasAnyPermission } from '../src/index.js'

// User must have ALL of these:
if (!hasPermission(user.permissions, ['orders:read', 'orders:write'])) {
    throw new ForbiddenError('Insufficient permissions')
}

// User needs ANY ONE of these:
if (!hasAnyPermission(user.permissions, ['admin', 'superuser'])) {
    throw new ForbiddenError('Admin access required')
}
```

### Wildcard admin permission

```js
hasPermission(['*'], 'anything:at:all')    // true
hasAnyPermission(['*'], ['x', 'y', 'z'])   // true
```

## Constraints / Gotchas

- **Algorithm is fixed**: always HMAC-SHA256. There is no option to choose RS256 or other algorithms.
- **`sign` adds `iat` unconditionally**: the issued-at claim is always present in the payload. Do not rely on its absence.
- **`expiresIn` is in seconds**, not milliseconds. Passing millisecond values (e.g. `3600000`) will create tokens that expire far in the future.
- **`verify` does not accept expired tokens**: there is no `ignoreExpiration` option. Use `decode` if you need to inspect an expired token.
- **`validateApiKey` never throws**: it silently returns `false` on empty strings, type mismatches, or hash length mismatch. Check that both `key` and `storedHash` are non-empty strings before calling if you need to distinguish "wrong key" from "bad arguments".
- **`hashApiKey` is deterministic**: the same key + secret always produces the same hash. This is intentional for validation, but means you cannot use it to generate unique IDs.
- **API key lookup strategy**: `validateApiKey` does not query a database. You must implement a lookup strategy (e.g., store a hash prefix as an index, or iterate all keys if the dataset is small).
- **`hasPermission` / `hasAnyPermission` are case-sensitive**: `'Admin'` and `'admin'` are different permissions.
- **`'*'` wildcard is a literal string**: it must be an element of the `userPermissions` array, not a glob pattern.

---

## Knowledge Base

**KB tags for this library:** `imagic-auth, authentication, jwt`

Before COMPLEX tasks — invoke `knowledge-reader` with tags above + task-specific tags.
After completing a task — if a reusable pattern, error, or decision emerged, invoke `knowledge-writer` with `source: imagic-auth`.

See `CLAUDE.md` §Knowledge Base Protocol for the full workflow.
