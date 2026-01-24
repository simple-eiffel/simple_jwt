# S02: CLASS CATALOG - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Class Hierarchy

```
SIMPLE_JWT (main class)

SIMPLE_JWT_QUICK (convenience, uses SIMPLE_JWT)
```

## Class Descriptions

### SIMPLE_JWT

| Attribute | Value |
|-----------|-------|
| Type | Effective class |
| Role | JWT creation and verification |
| LOC | ~615 |
| Features | 30+ |

**Purpose**: Complete JWT handling including creation, verification, and claim extraction.

**Key Components**:
- Token creation (with claims)
- Multiple verification methods
- Claim extraction
- Security features

### SIMPLE_JWT_QUICK

| Attribute | Value |
|-----------|-------|
| Type | Effective class |
| Role | Convenience API |
| LOC | ~100 |
| Pattern | Facade |

**Purpose**: Simplified API for common JWT operations.

## Class Dependencies

```
SIMPLE_JWT
    |
    +-- uses SIMPLE_BASE64 (encoding)
    +-- uses SIMPLE_HASH (HMAC, secure compare)
    +-- uses SIMPLE_UUID (jti generation)
    +-- uses SIMPLE_DATE_TIME (timestamps)
    +-- uses JSON_PARSER (claims)
    +-- uses JSON_OBJECT (claims)
```

## Class Metrics

| Class | LOC | Features | Contracts |
|-------|-----|----------|-----------|
| SIMPLE_JWT | 615 | 32 | 20 |
| SIMPLE_JWT_QUICK | 100 | 8 | 4 |
| **Total** | 715 | 40 | 24 |
