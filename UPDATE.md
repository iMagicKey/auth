# UPDATE — imagic-auth

> Audit performed: 2026-04-07. Version at time of audit: 1.0.2

---

## Owner decisions

- [ ] `hasPermission(perms, [])` returns true, so a computed empty requirement fails open (audit AU-04). The docs do not define it and `tests/auth.test.js` and `tests/permissions.test.js` assert it. `hasAnyPermission(perms, [])` returns false, except `true` for a `'*'` holder.
- [ ] An empty string is a valid requirement: `hasPermission(['*'], '')` returns true.

---

## Security hardening

- [ ] Enforce or warn on a minimum secret length; one-character secrets are accepted (audit AU-03, RFC 8725 section 3.5)
- [ ] `generateApiKey({ length: 0 })` returns an empty string, and a stored hash with trailing non-hex characters still validates (audit AU-05)
- [ ] `decode` still parses base64url leniently, has no size limit and returns non-object headers and payloads, although its docs promise objects
- [ ] `verify` replaces invalid UTF-8 in a signed segment instead of rejecting it (RFC 7519 section 7.2)
- [ ] `sign` accepts an array payload and spreads it into an object, although AGENT.md says it throws
- [ ] `sign` issues a token that `verify` rejects when the payload has its own `toJSON` returning a non-object

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
