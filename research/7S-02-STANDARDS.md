# 7S-02: STANDARDS - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Applicable Standards

### JWT Standards

- **RFC 7519**: JSON Web Token (JWT)
- **RFC 7515**: JSON Web Signature (JWS) - partial
- **RFC 7518**: JSON Web Algorithms (JWA) - HS256 only

### Related Standards

- **RFC 4648**: Base64URL encoding
- **RFC 7516**: JSON Web Encryption (JWE) - NOT implemented

## Standards Compliance

### RFC 7519 (JWT)

| Feature | Compliance |
|---------|------------|
| JWT structure | Full |
| Registered claims | Full |
| Claim validation | Full |
| Nested JWT | Not supported |

### Registered Claims

| Claim | Name | Supported |
|-------|------|-----------|
| iss | Issuer | Yes |
| sub | Subject | Yes |
| aud | Audience | Yes (string or array) |
| exp | Expiration | Yes |
| nbf | Not Before | Yes |
| iat | Issued At | Yes |
| jti | JWT ID | Yes (UUID v4) |

### RFC 7515 (JWS)

| Feature | Compliance |
|---------|------------|
| Compact serialization | Full |
| JSON serialization | Not supported |
| Algorithm validation | Full |
| "none" rejection | Full |

### Security Features

| Feature | Status |
|---------|--------|
| Algorithm substitution prevention | Implemented |
| "none" algorithm rejection | Implemented |
| Constant-time signature comparison | Implemented |
| Clock skew tolerance | Configurable |
