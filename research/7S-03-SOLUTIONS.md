# 7S-03: SOLUTIONS - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Existing Solutions Comparison

### No Native Eiffel JWT Libraries

Before simple_jwt, Eiffel developers had limited options:
1. Manual implementation (error-prone)
2. C library bindings (complex)
3. External service calls (latency)

### simple_jwt Advantages

| Aspect | Value |
|--------|-------|
| Native Eiffel | Full void safety |
| Self-contained | No external dependencies |
| Security-focused | Timing attack prevention |
| Simple API | Easy to use correctly |

## Design Decisions

### Algorithm Choice: HS256 Only

**Rationale**:
- Most common symmetric algorithm
- Sufficient for internal services
- Simpler key management
- No RSA/ECDSA complexity

**Trade-off**: Cannot verify tokens from services using asymmetric algorithms.

### Security-First Design

1. **verify_secure**: Recommended method with algorithm validation
2. **Constant-time comparison**: Via simple_hash
3. **"none" rejection**: Explicit check
4. **Clock skew**: Configurable tolerance

### Dependency Strategy

Uses simple_* foundation:
- simple_base64 for encoding
- simple_hash for HMAC
- simple_uuid for jti generation
- simple_datetime for timestamps
