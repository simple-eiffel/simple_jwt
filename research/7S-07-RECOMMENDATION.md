# 7S-07: RECOMMENDATION - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Recommendation: COMPLETE

simple_jwt is **production-ready** for HS256 JWT use cases.

## Implementation Status

| Feature | Status |
|---------|--------|
| HS256 signing | Complete |
| Token creation | Complete |
| Standard claims | Complete |
| Custom claims | Complete |
| Secure verification | Complete |
| Algorithm validation | Complete |
| Timing attack prevention | Complete |
| Clock skew | Complete |
| Audience validation | Complete |
| NBF validation | Complete |
| JTI generation | Complete |

## Strengths

1. Security-first design
2. Algorithm substitution prevention
3. Constant-time comparison
4. Full void safety
5. Simple, hard-to-misuse API
6. Strong contracts
7. RFC 7519 compliant

## Limitations

1. HS256 only (no RSA/ECDSA)
2. No JWE (encryption)
3. No JWKS support
4. Single algorithm per instance

## When to Use

**Use simple_jwt when:**
- Internal service authentication
- Symmetric key scenarios
- HS256 is sufficient
- Simple JWT needs

**Don't use when:**
- Need asymmetric algorithms
- Consuming third-party JWTs with RS256
- Need encrypted tokens (JWE)
- Complex key management required

## Conclusion

simple_jwt delivers secure HS256 JWT handling with proper security hardening. Suitable for most internal authentication scenarios.
