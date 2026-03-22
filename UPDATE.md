# UPDATE — imagic-auth

## Critical bugs (fix immediately)
- [ ] None known

## package.json
- [ ] No issues

## ESLint
- [ ] No issues

## Tests
- [ ] Consider adding tests for token with no exp claim (verify does not throw)
- [ ] Consider testing decode with malformed base64url payload

## API improvements (minor bump)
- [ ] Add `RS256` support (asymmetric JWT signing)
- [ ] Add `refreshToken` utility for rotating JWT pairs
- [ ] Support `audience` and `issuer` claims in sign/verify

## Backlog
- [ ] Browser-compatible build (SubtleCrypto-based JWT)
- [ ] Permission inheritance / role-based permission expansion
