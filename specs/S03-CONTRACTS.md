# S03: CONTRACTS - simple_jwt

**Library**: simple_jwt
**Date**: 2026-01-23
**Status**: BACKWASH (reverse-engineered from implementation)

## SIMPLE_JWT Contracts

### Initialization Contracts

```eiffel
make (a_secret: STRING)
    require
        secret_not_void: a_secret /= Void
        secret_not_empty: not a_secret.is_empty
    ensure
        secret_set: secret = a_secret
        algorithm_hs256: algorithm.same_string ("HS256")
        no_clock_skew: clock_skew = 0
```

### Configuration Contracts

```eiffel
set_clock_skew (a_seconds: INTEGER)
    require
        non_negative: a_seconds >= 0
    ensure
        clock_skew_set: clock_skew = a_seconds
```

### Token Creation Contracts

```eiffel
create_token (a_claims: JSON_OBJECT): STRING
    require
        claims_not_void: a_claims /= Void
    ensure
        has_three_parts: Result.occurrences ('.') = 2

create_token_with_jti (a_claims: JSON_OBJECT): STRING
    require
        claims_not_void: a_claims /= Void
```

### Verification Contracts

```eiffel
verify (a_token: STRING): BOOLEAN
    require
        token_not_void: a_token /= Void

verify_secure (a_token: STRING): BOOLEAN
    require
        token_not_void: a_token /= Void

verify_with_algorithm (a_token: STRING; a_allowed_algorithm: STRING): BOOLEAN
    require
        token_not_void: a_token /= Void
        algorithm_not_void: a_allowed_algorithm /= Void
        algorithm_not_empty: not a_allowed_algorithm.is_empty

verify_full (a_token: STRING; a_expected_audience: detachable STRING): BOOLEAN
    require
        token_not_void: a_token /= Void
```

### Claim Extraction Contracts

```eiffel
get_claim (a_token: STRING; a_claim_name: STRING): detachable JSON_VALUE
    require
        token_not_void: a_token /= Void
        claim_name_not_void: a_claim_name /= Void
```

## Class Invariant

```eiffel
invariant
    secret_exists: secret /= Void
    secret_not_empty: not secret.is_empty
    algorithm_set: algorithm /= Void
    base64_exists: base64 /= Void
    hasher_exists: hasher /= Void
    uuid_gen_exists: uuid_gen /= Void
    clock_skew_non_negative: clock_skew >= 0
```
