# S01: PROJECT INVENTORY - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Project Overview

| Attribute | Value |
|-----------|-------|
| Library Name | simple_jwt |
| Purpose | JWT creation and verification |
| Phase | Production |
| Void Safety | Full |
| SCOOP Ready | Yes |

## File Inventory

### Source Files

| File | Path | Purpose |
|------|------|---------|
| simple_jwt.e | src/ | Main JWT class |
| simple_jwt_quick.e | src/ | Convenience API |

### Test Files

| File | Path | Purpose |
|------|------|---------|
| test_app.e | testing/ | Test application root |
| lib_tests.e | testing/ | Test cases |

### Configuration

| File | Purpose |
|------|---------|
| simple_jwt.ecf | Library ECF |

## External Dependencies

### simple_* Libraries

| Library | Usage |
|---------|-------|
| simple_base64 | Base64URL encoding |
| simple_hash | HMAC-SHA256, secure compare |
| simple_uuid | JTI generation |
| simple_datetime | Timestamp handling |

### EiffelStudio Libraries

| Library | Usage |
|---------|-------|
| json | Claims parsing |
| base | Core types |

## Build Artifacts

| Target | Output |
|--------|--------|
| simple_jwt | Library (linkable) |
| simple_jwt_tests | Test executable |
