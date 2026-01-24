# S05: CONSTRAINTS - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Algorithm Constraints

### Supported Algorithms

| Algorithm | Supported | Notes |
|-----------|-----------|-------|
| HS256 | Yes | HMAC-SHA256 |
| HS384 | No | Not implemented |
| HS512 | No | Not implemented |
| RS256 | No | Requires RSA |
| RS384 | No | Requires RSA |
| RS512 | No | Requires RSA |
| ES256 | No | Requires ECDSA |
| none | Rejected | Security |

### Algorithm Header

Fixed header for all tokens:
```json
{"alg":"HS256","typ":"JWT"}
```

## Token Structure Constraints

### Format

```
BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
```

### Validation Rules

1. Must have exactly 3 parts (2 dots)
2. Header must contain "alg" claim
3. Header "alg" must match expected (HS256)
4. "none" algorithm always rejected

## Time Constraints

### Expiration (exp)

- Validates: `current_time <= exp + clock_skew`
- If exp not present: Token considered non-expiring

### Not Before (nbf)

- Validates: `current_time >= nbf - clock_skew`
- If nbf not present: Token immediately valid

### Clock Skew

- Default: 0 seconds
- Recommended: 30-60 seconds
- Purpose: Handle clock drift between systems

## Secret Constraints

| Constraint | Value | Reason |
|------------|-------|--------|
| Minimum length | 1 char | Precondition |
| Recommended | 32+ bytes | Security |
| Maximum | None | Memory only |

## Audience Constraints

- Can be string or array of strings
- verify_with_audience checks for exact match
- At least one audience must match
