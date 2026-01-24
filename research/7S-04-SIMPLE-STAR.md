# 7S-04: SIMPLE-STAR INTEGRATION - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Ecosystem Position

simple_jwt provides JWT authentication for the simple_* ecosystem.

## Dependencies (Inbound)

| Library | Usage |
|---------|-------|
| simple_base64 | Base64URL encoding/decoding |
| simple_hash | HMAC-SHA256, secure compare |
| simple_uuid | JWT ID generation |
| simple_datetime | Timestamp handling |
| EiffelStudio json | Claims parsing |

## Dependents (Outbound)

| Library | How It Uses simple_jwt |
|---------|----------------------|
| simple_http | API authentication headers |
| simple_auth | Token-based authentication |

## Integration Pattern

### Token Creation

```eiffel
local
    jwt: SIMPLE_JWT
    token: STRING
do
    create jwt.make ("my-secret-key")
    token := jwt.create_token_with_claims (
        "user-123",     -- subject
        "my-app",       -- issuer
        3600,           -- expiration (1 hour)
        custom_claims   -- optional
    )
end
```

### Token Verification

```eiffel
if jwt.verify_full (token, "expected-audience") then
    if attached jwt.get_string_claim (token, "sub") as subject then
        -- Authenticated as subject
    end
else
    -- Invalid token
end
```

## Ecosystem Conventions

1. **Naming**: SIMPLE_ prefix
2. **Error handling**: Boolean returns + detachable claims
3. **Security defaults**: verify_secure recommended
4. **Void safety**: Full
