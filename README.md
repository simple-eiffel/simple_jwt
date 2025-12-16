<p align="center">
  <img src="https://raw.githubusercontent.com/simple-eiffel/claude_eiffel_op_docs/main/artwork/LOGO.png" alt="simple_ library logo" width="400">
</p>

# simple_jwt

**[Documentation](https://simple-eiffel.github.io/simple_jwt/)** | **[Watch the Build Video](https://youtu.be/Rh3KhoK_W5U)**

JSON Web Token (JWT) library for Eiffel.

## Features

- **HS256 Algorithm** - HMAC-SHA256 signing
- **Token Creation** - Generate signed JWTs
- **Token Verification** - Validate signatures and expiration
- **Claims Decoding** - Extract payload data
- **Design by Contract** - Full preconditions/postconditions
- **RFC 7519 Compliant** - Standard JWT implementation

## Installation

Add to your ECF:

```xml
<library name="simple_jwt" location="$SIMPLE_JWT\simple_jwt.ecf"/>
```

Set environment variables:
```
SIMPLE_JWT=D:\prod\simple_jwt
SIMPLE_FOUNDATION_API=D:\prod\simple_foundation_api
```

Note: simple_jwt uses simple_foundation_api for encoding and hashing operations.

## Quick Start (Zero-Configuration)

Use `SIMPLE_JWT_QUICK` for the simplest possible JWT operations:

```eiffel
local
    jwt: SIMPLE_JWT_QUICK
    token: STRING
do
    -- Create JWT handler (secret should be 32+ chars for security)
    create jwt.make ("your-super-secret-key-at-least-32-chars")

    -- Create token for user (no expiration)
    token := jwt.create_for_user ("user123")

    -- Create token with expiration (24 hours)
    token := jwt.create_with_expiry ("user123", 24)

    -- Verify token
    if jwt.is_valid (token) then
        print ("User: " + jwt.get_user_id (token))
    end

    -- Check expiration
    if jwt.is_expired (token) then
        print ("Token expired - please login again")
    end

    -- Get custom claims
    if attached jwt.get_claim (token, "role") as role then
        print ("User role: " + role)
    end

    -- Error info
    if not jwt.is_valid (token) then
        print ("Invalid: " + jwt.last_error)
    end
end
```

## Standard API (Full Control)

### Create a Token

```eiffel
local
    jwt: SIMPLE_JWT
    token: STRING
do
    create jwt.make ("your-secret-key")

    token := jwt.create_token_with_claims (
        "user@example.com",  -- subject
        "my-application",    -- issuer
        3600,                -- expires in 1 hour
        Void                 -- no custom claims
    )
end
```

### Verify a Token

```eiffel
local
    jwt: SIMPLE_JWT
do
    create jwt.make ("your-secret-key")

    if jwt.verify_with_expiration (token) then
        print ("Token is valid%N")
    end
end
```

### Decode Claims

```eiffel
local
    jwt: SIMPLE_JWT
    subject: detachable STRING
do
    create jwt.make ("secret")

    subject := jwt.get_string_claim (token, "sub")

    if attached jwt.decode_claims (token) as claims then
        -- Access any claim
    end
end
```

### Custom Claims

```eiffel
local
    jwt: SIMPLE_JWT
    custom: JSON_OBJECT
do
    create jwt.make ("secret")
    create custom.make_empty
    custom.put_string ("admin", "role")
    custom.put_integer (12345, "user_id")

    token := jwt.create_token_with_claims ("admin", "app", 7200, custom)
end
```

## API Reference

### Token Creation

| Feature | Description |
|---------|-------------|
| `create_token (claims)` | Create JWT from JSON claims |
| `create_token_with_claims (sub, iss, exp, custom)` | Create JWT with standard claims |

### Token Verification

| Feature | Description |
|---------|-------------|
| `verify (token)` | Verify signature only |
| `verify_with_expiration (token)` | Verify signature and expiration |
| `is_expired (token)` | Check if token is expired |

### Token Decoding

| Feature | Description |
|---------|-------------|
| `decode_claims (token)` | Get payload as JSON_OBJECT |
| `decode_header (token)` | Get header as JSON_OBJECT |
| `get_string_claim (token, name)` | Get string claim |
| `get_integer_claim (token, name)` | Get integer claim |

## JWT Structure

```
header.payload.signature
```

- **Header**: `{"alg":"HS256","typ":"JWT"}`
- **Payload**: Claims (sub, iss, iat, exp, custom)
- **Signature**: HMAC-SHA256(header.payload, secret)

## Dependencies

- simple_foundation_api - Base64URL encoding, HMAC-SHA256 signatures, UUID generation
- json - JSON parsing (EiffelStudio contrib)

## License

MIT License - Copyright (c) 2024-2025, Larry Rix
