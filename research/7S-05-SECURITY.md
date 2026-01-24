# 7S-05: SECURITY - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## Security Considerations

### Threat Model

| Threat | Risk | Mitigation |
|--------|------|------------|
| Algorithm substitution | Critical | verify_secure validates alg |
| "none" algorithm attack | Critical | Explicit rejection |
| Timing attack | High | Constant-time comparison |
| Clock skew | Medium | Configurable tolerance |
| Token replay | Medium | jti claim support |
| Secret exposure | High | Secrets in memory only |

### Security Features

#### Algorithm Validation

```eiffel
verify_with_algorithm (a_token: STRING; a_allowed_algorithm: STRING): BOOLEAN
    -- Rejects tokens with mismatched algorithms
    -- CRITICAL for preventing algorithm substitution attacks
```

#### "none" Algorithm Rejection

```eiffel
is_none_algorithm (a_alg: STRING): BOOLEAN
    -- Case-insensitive check for "none"
    -- Always rejected in verify_secure
```

#### Constant-Time Comparison

```eiffel
Result := hasher.secure_compare (l_parts [3], l_expected_sig)
    -- Prevents timing attacks by comparing in constant time
```

## Security Best Practices

### Do

1. Use `verify_secure` or `verify_full` in production
2. Set appropriate clock skew (30-60 seconds typical)
3. Validate audience for multi-tenant systems
4. Use strong secrets (32+ bytes)
5. Short expiration times

### Don't

1. Use `verify` alone (no algorithm check)
2. Ignore expiration checking
3. Store secrets in code
4. Use predictable secrets

## Security Limitations

- HS256 only (shared secret)
- No key rotation mechanism
- No token revocation
- Secret in memory (no HSM support)
