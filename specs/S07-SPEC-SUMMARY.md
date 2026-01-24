# S07: SPECIFICATION SUMMARY - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Executive Summary

simple_jwt provides secure HS256 JWT handling for Eiffel applications with algorithm validation, timing attack prevention, and comprehensive claim support.

## Key Specifications

### Architecture

- **Pattern**: Single class with helpers
- **Classes**: 2
- **LOC**: ~715

### RFC Compliance

| RFC | Feature | Status |
|-----|---------|--------|
| 7519 | JWT | Full (HS256) |
| 7515 | JWS | Partial |
| 7518 | JWA | HS256 only |

### API Surface

| Category | Methods |
|----------|---------|
| Creation | 3 |
| Verification | 7 |
| Claim extraction | 5 |
| Token parts | 3 |
| Configuration | 2 |

### Security Features

| Feature | Status |
|---------|--------|
| Algorithm validation | Yes |
| "none" rejection | Yes |
| Constant-time compare | Yes |
| Clock skew | Configurable |
| Audience check | Yes |
| NBF validation | Yes |

## Design Decisions

1. **HS256 only**: Simplicity over flexibility
2. **Security-first**: verify_secure as recommended
3. **Timing attack prevention**: Constant-time comparison
4. **Clock tolerance**: Configurable skew

## Quality Attributes

| Attribute | Rating |
|-----------|--------|
| Security | Excellent |
| Usability | Good |
| Simplicity | Excellent |
| Extensibility | Limited (by design) |
