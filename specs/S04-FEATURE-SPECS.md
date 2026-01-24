# S04: FEATURE SPECIFICATIONS - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## SIMPLE_JWT Features

### Initialization

| Feature | Signature | Description |
|---------|-----------|-------------|
| make | (secret: STRING) | Create JWT handler with secret |

### Configuration

| Feature | Signature | Description |
|---------|-----------|-------------|
| set_clock_skew | (seconds: INTEGER) | Set tolerance for time checks |
| clock_skew | : INTEGER | Current tolerance (seconds) |

### Token Creation

| Feature | Signature | Description |
|---------|-----------|-------------|
| create_token | (claims: JSON_OBJECT): STRING | Create JWT with claims |
| create_token_with_claims | (sub, iss, exp, custom): STRING | Create with standard claims |
| create_token_with_jti | (claims): STRING | Create with auto UUID |

### Token Verification

| Feature | Signature | Description |
|---------|-----------|-------------|
| verify | (token): BOOLEAN | Basic signature check |
| verify_secure | (token): BOOLEAN | With algorithm validation |
| verify_with_algorithm | (token, alg): BOOLEAN | Specific algorithm |
| verify_with_expiration | (token): BOOLEAN | Check exp claim |
| verify_with_audience | (token, aud): BOOLEAN | Check aud claim |
| verify_nbf | (token): BOOLEAN | Check not-before |
| verify_full | (token, aud): BOOLEAN | All checks combined |
| is_expired | (token): BOOLEAN | Check if expired |

### Claim Decoding

| Feature | Signature | Description |
|---------|-----------|-------------|
| decode_claims | (token): detachable JSON_OBJECT | Get payload as JSON |
| decode_header | (token): detachable JSON_OBJECT | Get header as JSON |
| get_claim | (token, name): detachable JSON_VALUE | Get specific claim |
| get_string_claim | (token, name): detachable STRING | Get string claim |
| get_integer_claim | (token, name): INTEGER_64 | Get integer claim |

### Token Parts

| Feature | Signature | Description |
|---------|-----------|-------------|
| extract_header | (token): STRING | Get Base64URL header |
| extract_payload | (token): STRING | Get Base64URL payload |
| extract_signature | (token): STRING | Get Base64URL signature |

### Internal Features

| Feature | Visibility | Description |
|---------|------------|-------------|
| create_signature | NONE | HMAC-SHA256 signing |
| base64_url_encode | NONE | URL-safe Base64 |
| base64_url_decode | NONE | URL-safe Base64 decode |
| is_none_algorithm | NONE | Security check |
| current_unix_time | NONE | Timestamp helper |
