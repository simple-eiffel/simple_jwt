<p align="center">
  <img src="https://raw.githubusercontent.com/ljr1981/claude_eiffel_op_docs/main/artwork/LOGO.png" alt="simple_ library logo" width="400">
</p>

# simple_jwt

**[Documentation](https://ljr1981.github.io/simple_jwt/)**

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
SIMPLE_BASE64=D:\prod\simple_base64
SIMPLE_HASH=D:\prod\simple_hash
```

## Usage

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

- simple_base64 - Base64URL encoding
- simple_hash - HMAC-SHA256 signatures
- json - JSON parsing (EiffelStudio contrib)

## License

MIT License - Copyright (c) 2024-2025, Larry Rix
