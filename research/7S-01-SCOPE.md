# 7S-01: SCOPE - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Problem Domain

JSON Web Token (JWT) creation and verification for Eiffel applications.

### What Problem Does This Solve?

1. **Token-based Authentication**: Create and verify JWTs for stateless auth
2. **API Security**: Sign requests, validate responses
3. **Claims Management**: Standard and custom claims
4. **Security**: Algorithm validation, timing attack prevention

### Target Users

- Eiffel developers building authenticated APIs
- Applications consuming JWT-protected services
- Microservices requiring token-based auth

### Use Cases

1. Issue JWTs for authenticated users
2. Verify incoming JWTs on API requests
3. Extract claims from tokens
4. Handle token expiration and timing

## Boundaries

### In Scope

- HS256 (HMAC-SHA256) algorithm
- Standard claims (iss, sub, aud, exp, nbf, iat, jti)
- Custom claims
- Token creation
- Secure verification
- Clock skew handling
- Audience validation

### Out of Scope

- RS256/RS384/RS512 (RSA algorithms)
- ES256/ES384/ES512 (ECDSA algorithms)
- JWS (signed only, not encrypted)
- JWE (encrypted tokens)
- JWKS (key sets)
- Token refresh mechanisms

## Domain Vocabulary

| Term | Definition |
|------|------------|
| JWT | JSON Web Token - encoded claims with signature |
| Header | Algorithm and type metadata (Base64URL) |
| Payload | Claims JSON (Base64URL) |
| Signature | HMAC of header.payload |
| Claim | Key-value assertion in payload |
| HS256 | HMAC-SHA256 algorithm |
