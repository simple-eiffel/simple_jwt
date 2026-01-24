# S06: BOUNDARIES - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## System Boundaries

### What simple_jwt IS

- HS256 JWT creation
- JWT verification with security checks
- Standard claim handling
- Custom claim support
- Base64URL encoding

### What simple_jwt IS NOT

- Asymmetric algorithm support (RS256, ES256)
- JWE (encrypted tokens)
- JWKS (key set management)
- Token storage
- Key rotation
- Token refresh service

## API Boundaries

### Public API

All features of SIMPLE_JWT and SIMPLE_JWT_QUICK:
- Token creation
- Token verification
- Claim extraction
- Configuration

### Internal API

- Signature creation
- Base64 operations
- Algorithm validation
- Time calculations

## Security Boundaries

### Protected Operations

| Operation | Protection |
|-----------|------------|
| Algorithm selection | Fixed to HS256 |
| "none" algorithm | Rejected |
| Signature comparison | Constant-time |
| Clock handling | Skew-tolerant |

### User Responsibility

| Aspect | User Must Handle |
|--------|-----------------|
| Secret storage | Secure storage |
| Secret strength | Sufficient entropy |
| Token transmission | HTTPS |
| Token storage | Secure client storage |

## Integration Boundaries

### Compatible With

| Library | Integration |
|---------|-------------|
| simple_http | Auth headers |
| simple_json | Claim handling |

### Dependency Chain

```
simple_jwt
    +-- simple_base64
    +-- simple_hash
    +-- simple_uuid
    +-- simple_datetime
    +-- json (EiffelStudio)
```
