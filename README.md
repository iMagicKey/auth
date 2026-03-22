# imagic-auth

> JWT signing/verification, API key utilities, and permission checking for Node.js.

## Install

```bash
npm install imagic-auth
```

## Quick Start

```js
import { sign, verify, generateApiKey, hashApiKey, validateApiKey, hasPermission } from 'imagic-auth'

// JWT
const token = sign({ userId: 42, role: 'admin' }, 'my-secret', { expiresIn: 3600 })
const payload = verify(token, 'my-secret')
// { userId: 42, role: 'admin', iat: 1700000000, exp: 1700003600 }

// API keys
const key = generateApiKey({ prefix: 'sk', length: 32 })  // 'sk_a1b2c3...'
const hash = hashApiKey(key, 'storage-secret')
const ok = validateApiKey(key, hash, 'storage-secret')     // true

// Permissions
hasPermission(['users:read', 'users:write'], 'users:read') // true
hasPermission(['*'], 'anything')                            // true
```

## API

### JWT

#### `sign(payload, secret, options?)`

```ts
sign(
    payload: Record<string, unknown>,
    secret: string,
    options?: { expiresIn?: number }
): string
```

Signs `payload` with HMAC-SHA256 and returns a JWT string (header.payload.signature, all base64url-encoded).

| Parameter | Type | Description |
|-----------|------|-------------|
| `payload` | `object` | Data to embed; must be a plain object |
| `secret` | `string` | Non-empty signing secret |
| `options.expiresIn` | `number` | Expiry in **seconds** from now. Adds `exp` claim. |

Always adds an `iat` (issued-at) claim set to the current Unix timestamp.

Throws `TypeError` if `secret` is not a non-empty string or `payload` is not an object.

---

#### `verify(token, secret)`

```ts
verify(token: string, secret: string): Record<string, unknown>
```

Verifies the token signature and expiry. Returns the decoded payload on success.

| Throws | When |
|--------|------|
| `Error('Invalid token format')` | Token is not a 3-part JWT string |
| `Error('Invalid signature')` | Signature does not match |
| `Error('Token expired')` | `exp` claim is in the past |
| `Error('Invalid token payload')` | Payload cannot be decoded |

---

#### `decode(token)`

```ts
decode(token: string): { header: object, payload: object }
```

Decodes a JWT **without** verifying the signature. Useful for inspecting tokens without a secret.

Throws `TypeError` if `token` is not a string. Throws `Error` if the format is invalid.

---

### API Keys

#### `generateApiKey(options?)`

```ts
generateApiKey(options?: { length?: number, prefix?: string }): string
```

Generates a cryptographically secure API key using `crypto.randomBytes`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `length` | `number` | `32` | Number of random bytes; output is `length * 2` hex characters |
| `prefix` | `string` | `''` | Prefix prepended as `{prefix}_{hex}`. Omitted when empty. |

Each call returns a unique value. There is no way to reproduce a previous key.

---

#### `hashApiKey(key, secret)`

```ts
hashApiKey(key: string, secret: string): string
```

Returns an HMAC-SHA256 hex digest of `key` using `secret`. Use this to store API keys safely — store the hash, not the raw key.

Throws `TypeError` if either `key` or `secret` is an empty string.

---

#### `validateApiKey(key, storedHash, secret)`

```ts
validateApiKey(key: string, storedHash: string, secret: string): boolean
```

Re-hashes `key` with `secret` and compares against `storedHash` using a timing-safe comparison (`crypto.timingSafeEqual`).

Returns `false` on any error (wrong types, empty strings, hash length mismatch). Never throws.

---

### Permissions

#### `hasPermission(userPermissions, required)`

```ts
hasPermission(userPermissions: string[], required: string | string[]): boolean
```

Returns `true` if the user holds **all** of the required permissions.

- `'*'` in `userPermissions` grants everything.
- Returns `false` if `userPermissions` is not an array.

```js
hasPermission(['posts:read', 'posts:write'], ['posts:read', 'posts:write']) // true
hasPermission(['posts:read'], 'posts:write')                                // false
hasPermission(['*'], 'any:permission')                                      // true
```

---

#### `hasAnyPermission(userPermissions, required)`

```ts
hasAnyPermission(userPermissions: string[], required: string | string[]): boolean
```

Returns `true` if the user holds **at least one** of the required permissions.

- `'*'` in `userPermissions` grants everything.
- Returns `false` if `userPermissions` is not an array.

```js
hasAnyPermission(['posts:read'], ['posts:read', 'posts:write']) // true
hasAnyPermission(['comments:read'], 'posts:write')             // false
```

## Error Handling

| Function | Throws | When |
|----------|--------|------|
| `sign` | `TypeError` | `secret` is empty or `payload` is not an object |
| `verify` | `Error` | Invalid format, wrong signature, expired, bad payload |
| `decode` | `TypeError` | `token` is not a string |
| `decode` | `Error` | Invalid JWT format |
| `hashApiKey` | `TypeError` | `key` or `secret` is empty |
| `validateApiKey` | never | Returns `false` on all error conditions |
| `hasPermission` | never | Returns `false` on bad input |
| `hasAnyPermission` | never | Returns `false` on bad input |

## Examples

See [`examples/basic.js`](./examples/basic.js) for a runnable demo:

```bash
node examples/basic.js
```

## License

MIT
