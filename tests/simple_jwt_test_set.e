note
	description: "Tests for SIMPLE_JWT"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	testing: "type/manual"

class
	SIMPLE_JWT_TEST_SET

inherit
	TEST_SET_BASE

feature -- Test: Token Creation

	test_create_token_basic
			-- Test basic token creation.
		note
			testing: "covers/{SIMPLE_JWT}.create_token"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_string ("user123", "sub")
			token := jwt.create_token (claims)
			assert ("token not empty", not token.is_empty)
			assert_integers_equal ("three parts", 2, token.occurrences ('.'))
		end

	test_create_token_with_claims
			-- Test token creation with standard claims.
		note
			testing: "covers/{SIMPLE_JWT}.create_token_with_claims"
		local
			jwt: SIMPLE_JWT
			token: STRING
		do
			create jwt.make ("my-secret-key")
			token := jwt.create_token_with_claims ("user@example.com", "my-app", 3600, Void)
			assert ("token created", not token.is_empty)
		end

	test_create_token_with_custom_claims
			-- Test token creation with custom claims.
		note
			testing: "covers/{SIMPLE_JWT}.create_token_with_claims"
		local
			jwt: SIMPLE_JWT
			custom: JSON_OBJECT
			token: STRING
		do
			create jwt.make ("secret")
			create custom.make_empty
			custom.put_string ("admin", "role")
			custom.put_integer (42, "user_id")
			token := jwt.create_token_with_claims ("admin", "system", 7200, custom)
			assert ("token with custom", not token.is_empty)
		end

feature -- Test: Token Verification

	test_verify_valid_token
			-- Test verification of valid token.
		note
			testing: "covers/{SIMPLE_JWT}.verify"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
		do
			create jwt.make ("test-secret")
			create claims.make_empty
			claims.put_string ("test", "sub")
			token := jwt.create_token (claims)
			assert ("valid signature", jwt.verify (token))
		end

	test_verify_invalid_signature
			-- Test verification fails with wrong secret.
		note
			testing: "covers/{SIMPLE_JWT}.verify"
		local
			jwt1, jwt2: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
		do
			create jwt1.make ("secret1")
			create jwt2.make ("secret2")
			create claims.make_empty
			claims.put_string ("test", "sub")
			token := jwt1.create_token (claims)
			assert ("wrong secret fails", not jwt2.verify (token))
		end

	test_verify_tampered_payload
			-- Test verification fails when payload is tampered.
		note
			testing: "covers/{SIMPLE_JWT}.verify"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
			parts: LIST [STRING]
			tampered: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_string ("user", "sub")
			token := jwt.create_token (claims)

			-- Tamper with payload
			parts := token.split ('.')
			tampered := parts [1] + ".dGFtcGVyZWQ." + parts [3]

			assert ("tampered fails", not jwt.verify (tampered))
		end

	test_verify_with_expiration_valid
			-- Test verification with non-expired token.
		note
			testing: "covers/{SIMPLE_JWT}.verify_with_expiration"
		local
			jwt: SIMPLE_JWT
			token: STRING
		do
			create jwt.make ("secret")
			-- Token expires in 1 hour
			token := jwt.create_token_with_claims ("user", "app", 3600, Void)
			assert ("not expired", jwt.verify_with_expiration (token))
		end

	test_verify_with_expiration_no_exp
			-- Test verification of token without expiration.
		note
			testing: "covers/{SIMPLE_JWT}.verify_with_expiration"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_string ("user", "sub")
			token := jwt.create_token (claims)
			assert ("no exp is valid", jwt.verify_with_expiration (token))
		end

feature -- Test: Token Decoding

	test_decode_claims
			-- Test decoding payload claims.
		note
			testing: "covers/{SIMPLE_JWT}.decode_claims"
		local
			jwt: SIMPLE_JWT
			claims, decoded: JSON_OBJECT
			token: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_string ("john@example.com", "sub")
			claims.put_string ("my-issuer", "iss")
			token := jwt.create_token (claims)

			decoded := jwt.decode_claims (token)
			assert ("decoded not void", decoded /= Void)
			if attached decoded as d then
				assert ("has sub", d.has_key ("sub"))
				assert ("has iss", d.has_key ("iss"))
			end
		end

	test_decode_header
			-- Test decoding header.
		note
			testing: "covers/{SIMPLE_JWT}.decode_header"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
			header: detachable JSON_OBJECT
		do
			create jwt.make ("secret")
			create claims.make_empty
			token := jwt.create_token (claims)

			header := jwt.decode_header (token)
			assert ("header not void", header /= Void)
			if attached header as h then
				if attached {JSON_STRING} h.item ("alg") as alg then
					assert_strings_equal ("algorithm", "HS256", alg.unescaped_string_8)
				end
				if attached {JSON_STRING} h.item ("typ") as typ then
					assert_strings_equal ("type", "JWT", typ.unescaped_string_8)
				end
			end
		end

	test_get_string_claim
			-- Test getting string claim.
		note
			testing: "covers/{SIMPLE_JWT}.get_string_claim"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_string ("test-subject", "sub")
			token := jwt.create_token (claims)

			if attached jwt.get_string_claim (token, "sub") as sub then
				assert_strings_equal ("subject", "test-subject", sub)
			else
				assert ("sub should exist", False)
			end
		end

	test_get_integer_claim
			-- Test getting integer claim.
		note
			testing: "covers/{SIMPLE_JWT}.get_integer_claim"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
			user_id: INTEGER_64
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_integer (12345, "user_id")
			token := jwt.create_token (claims)

			user_id := jwt.get_integer_claim (token, "user_id")
			assert_integers_64_equal ("user_id", 12345, user_id)
		end

feature -- Test: Token Parts

	test_extract_header
			-- Test extracting header part.
		note
			testing: "covers/{SIMPLE_JWT}.extract_header"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token, header: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			token := jwt.create_token (claims)
			header := jwt.extract_header (token)
			assert ("header not empty", not header.is_empty)
			assert ("no dots", not header.has ('.'))
		end

	test_extract_payload
			-- Test extracting payload part.
		note
			testing: "covers/{SIMPLE_JWT}.extract_payload"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token, payload: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_string ("test", "sub")
			token := jwt.create_token (claims)
			payload := jwt.extract_payload (token)
			assert ("payload not empty", not payload.is_empty)
		end

	test_extract_signature
			-- Test extracting signature part.
		note
			testing: "covers/{SIMPLE_JWT}.extract_signature"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token, sig: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			token := jwt.create_token (claims)
			sig := jwt.extract_signature (token)
			assert ("signature not empty", not sig.is_empty)
		end

feature -- Test: Expiration

	test_is_expired_false
			-- Test is_expired returns false for non-expired token.
		note
			testing: "covers/{SIMPLE_JWT}.is_expired"
		local
			jwt: SIMPLE_JWT
			token: STRING
		do
			create jwt.make ("secret")
			token := jwt.create_token_with_claims ("user", "app", 3600, Void)
			assert ("not expired", not jwt.is_expired (token))
		end

	test_is_expired_no_exp_claim
			-- Test is_expired returns false when no exp claim.
		note
			testing: "covers/{SIMPLE_JWT}.is_expired"
		local
			jwt: SIMPLE_JWT
			claims: JSON_OBJECT
			token: STRING
		do
			create jwt.make ("secret")
			create claims.make_empty
			claims.put_string ("user", "sub")
			token := jwt.create_token (claims)
			assert ("no exp means not expired", not jwt.is_expired (token))
		end

feature -- Test: Consistency

	test_same_input_same_output
			-- Test same claims produce same token.
		note
			testing: "covers/{SIMPLE_JWT}.create_token"
		local
			jwt: SIMPLE_JWT
			claims1, claims2: JSON_OBJECT
			token1, token2: STRING
		do
			create jwt.make ("secret")
			create claims1.make_empty
			claims1.put_string ("user", "sub")
			create claims2.make_empty
			claims2.put_string ("user", "sub")
			token1 := jwt.create_token (claims1)
			token2 := jwt.create_token (claims2)
			assert_strings_equal ("deterministic", token1, token2)
		end

	test_different_secrets_different_tokens
			-- Test different secrets produce different signatures.
		note
			testing: "covers/{SIMPLE_JWT}.create_token"
		local
			jwt1, jwt2: SIMPLE_JWT
			claims: JSON_OBJECT
			token1, token2: STRING
		do
			create jwt1.make ("secret1")
			create jwt2.make ("secret2")
			create claims.make_empty
			claims.put_string ("user", "sub")
			token1 := jwt1.create_token (claims)
			token2 := jwt2.create_token (claims)
			assert ("different signatures", not token1.same_string (token2))
		end

end
