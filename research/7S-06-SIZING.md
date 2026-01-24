# 7S-06: SIZING - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Implementation Size

### Source Files

| Component | Lines | Classes |
|-----------|-------|---------|
| SIMPLE_JWT | ~615 | 1 |
| SIMPLE_JWT_QUICK | ~100 | 1 |
| **Total** | ~715 | 2 |

### Testing

| Component | Lines | Classes |
|-----------|-------|---------|
| LIB_TESTS | ~200 | 1 |
| TEST_APP | ~50 | 1 |
| **Total** | ~250 | 2 |

## Complexity Analysis

| Metric | Value |
|--------|-------|
| Cyclomatic complexity | Low-Medium |
| External dependencies | 4 simple_* libs |
| Security-sensitive code | High |
| Maintenance burden | Low |

## Feature Breakdown

| Feature | LOC | Complexity |
|---------|-----|------------|
| Token creation | ~100 | Low |
| Basic verification | ~50 | Low |
| Secure verification | ~80 | Medium |
| Full verification | ~100 | Medium |
| Claim extraction | ~100 | Low |
| Base64 operations | ~50 | Low |
| Time handling | ~50 | Low |

## Development Effort

### Initial Development

- Design: 2 hours
- Core implementation: 4 hours
- Security hardening: 3 hours
- Testing: 3 hours
- **Total**: ~12 hours

### Future Work Estimate

| Feature | Effort |
|---------|--------|
| RS256 support | 8 hours |
| ES256 support | 8 hours |
| JWKS support | 4 hours |
| Token refresh | 2 hours |
