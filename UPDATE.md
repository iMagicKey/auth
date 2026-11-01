# UPDATE — imagic-auth

> Audit performed: 2026-04-07. Version at time of audit: 1.0.2

---

## Owner decisions

- [ ] `hasPermission(perms, [])` returns true, so a computed empty requirement fails open (audit AU-04). The docs do not define it and `tests/auth.test.js` and `tests/permissions.test.js` assert it. `hasAnyPermission(perms, [])` returns false, except `true` for a `'*'` holder.
- [ ] An empty string is a valid requirement: `hasPermission(['*'], '')` returns true.

---

## Security hardening

- [ ] Enforce or warn on a minimum secret length; one-character secrets are accepted (audit AU-03, RFC 8725 section 3.5)
- [ ] `generateApiKey` accepts `{ length: 0 }`, which returns an empty string, and `{ length: 1 }`, which returns two hex characters (audit AU-05)
- [ ] `validateApiKey` accepts malformed stored hashes: trailing non-hex characters (`hash + 'zz'`), an odd trailing nibble, and uppercase hex (audit AU-05)
- [ ] `validateApiKey` accepts a Buffer, Uint8Array or byte array as the stored hash, although the README says wrong types return false
- [ ] Lone-surrogate secrets collide: `verify(sign(x, '\ud800'), '\ud801')` succeeds, because both encode to U+FFFD
- [ ] `hasPermission` and `hasAnyPermission` throw on a revoked Proxy or an array with a throwing getter, although the README says never; access is still denied because no `true` is returned
- [ ] `decode` still parses base64url leniently, has no size limit and returns non-object headers and payloads, although its docs promise objects
- [ ] `verify` replaces invalid UTF-8 in a signed segment instead of rejecting it (RFC 7519 section 7.2)

---

## API improvements (minor bump)

- [ ] Add `RS256` support (asymmetric JWT signing)
- [ ] Add `refreshToken` utility for rotating JWT pairs
- [ ] Support `audience` and `issuer` claims in sign/verify (audit AU-03, RFC 8725 sections 3.8 and 3.9)
- [ ] Add a `clockTolerance` option to `verify`: `exp` and `nbf` are now enforced to the millisecond with no skew allowance

---

## Backlog

- [ ] Browser-compatible build (SubtleCrypto-based JWT)
- [ ] Permission inheritance / role-based permission expansion
