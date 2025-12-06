note
	description: "[
		Simple JWT - JSON Web Token implementation for Eiffel.

		Supports:
		- HS256 (HMAC-SHA256) algorithm
		- Standard claims (iss, sub, aud, exp, nbf, iat, jti)
		- Custom claims
		- Token creation and verification

		JWT Structure:
			header.payload.signature
			- Header: {"alg":"HS256","typ":"JWT"} (Base64URL)
			- Payload: Claims JSON (Base64URL)
			- Signature: HMAC-SHA256 of header.payload

		Security Features:
		- Algorithm validation (prevents alg substitution attacks)
		- "none" algorithm rejection
		- Constant-time signature comparison (prevents timing attacks)
		- Clock skew tolerance for distributed systems
		- Audience validation
		- Not-before (nbf) validation

		Usage:
			create jwt.make ("secret-key")
			token := jwt.create_token (claims)
			if jwt.verify_secure (token) then ...   -- Use verify_secure for production!
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"
	EIS: "name=Documentation", "src=../docs/index.html", "protocol=URI", "tag=documentation"
	EIS: "name=API Reference", "src=../docs/api/simple_jwt.html", "protocol=URI", "tag=api"
	EIS: "name=RFC 7519", "src=https://datatracker.ietf.org/doc/html/rfc7519", "protocol=URI", "tag=specification"

class
	SIMPLE_JWT

create
	make

feature {NONE} -- Initialization

	make (a_secret: STRING)
			-- Initialize JWT handler with `a_secret' for HS256 signing.
		require
			secret_not_void: a_secret /= Void
			secret_not_empty: not a_secret.is_empty
		do
			secret := a_secret
			create foundation.make
			algorithm := "HS256"
			clock_skew := 0
		ensure
			secret_set: secret = a_secret
			algorithm_hs256: algorithm.same_string ("HS256")
			no_clock_skew: clock_skew = 0
		end

feature -- Configuration

	set_clock_skew (a_seconds: INTEGER)
			-- Set clock skew tolerance in seconds.
			-- Use this to account for clock drift in distributed systems.
			-- Typical value: 30-60 seconds.
		require
			non_negative: a_seconds >= 0
		do
			clock_skew := a_seconds
		ensure
			clock_skew_set: clock_skew = a_seconds
		end

	clock_skew: INTEGER
			-- Clock skew tolerance in seconds (default 0).

feature -- Token Creation

	create_token (a_claims: JSON_OBJECT): STRING
			-- Create a JWT with `a_claims' as payload.
		require
			claims_not_void: a_claims /= Void
		local
			l_header, l_payload, l_signature_input, l_signature: STRING
		do
			-- Create header
			l_header := base64_url_encode (header_json)

			-- Create payload
			l_payload := base64_url_encode (a_claims.representation)

			-- Create signature
			l_signature_input := l_header + "." + l_payload
			l_signature := create_signature (l_signature_input)

			-- Combine
			Result := l_signature_input + "." + l_signature
		ensure
			result_not_void: Result /= Void
			has_three_parts: Result.occurrences ('.') = 2
		end

	create_token_with_claims (a_subject: detachable STRING; a_issuer: detachable STRING;
			a_expiration_seconds: INTEGER; a_custom_claims: detachable JSON_OBJECT): STRING
			-- Create a JWT with standard claims.
			-- `a_expiration_seconds' is seconds from now (0 = no expiration).
		local
			l_claims: JSON_OBJECT
			l_now: INTEGER_64
		do
			create l_claims.make_empty

			-- Current time
			l_now := current_unix_time

			-- Standard claims
			if attached a_subject as l_sub then
				l_claims.put_string (l_sub, "sub")
			end
			if attached a_issuer as l_iss then
				l_claims.put_string (l_iss, "iss")
			end

			-- Issued at
			l_claims.put_integer (l_now, "iat")

			-- Expiration
			if a_expiration_seconds > 0 then
				l_claims.put_integer (l_now + a_expiration_seconds.to_integer_64, "exp")
			end

			-- Custom claims
			if attached a_custom_claims as l_custom then
				across l_custom.current_keys as k loop
					if attached l_custom.item (k.item) as l_val then
						l_claims.put (l_val, k.item)
					end
				end
			end

			Result := create_token (l_claims)
		ensure
			result_not_void: Result /= Void
		end

	create_token_with_jti (a_claims: JSON_OBJECT): STRING
			-- Create a JWT with auto-generated unique token ID (jti claim).
			-- Uses UUID v4 for jti generation.
		require
			claims_not_void: a_claims /= Void
		local
			l_jti: STRING
		do
			l_jti := foundation.new_uuid

			-- Add jti to claims (don't modify original)
			a_claims.put_string (l_jti, "jti")

			Result := create_token (a_claims)
		ensure
			result_not_void: Result /= Void
		end

feature -- Token Verification

	verify (a_token: STRING): BOOLEAN
			-- Verify `a_token' signature is valid.
			-- Does NOT check expiration - use `verify_with_expiration' for that.
			-- WARNING: Use `verify_secure' for production - this does not check algorithm.
		require
			token_not_void: a_token /= Void
		local
			l_parts: LIST [STRING]
			l_signature_input, l_expected_sig: STRING
		do
			l_parts := a_token.split ('.')
			if l_parts.count = 3 then
				l_signature_input := l_parts [1] + "." + l_parts [2]
				l_expected_sig := create_signature (l_signature_input)
				-- Use constant-time comparison to prevent timing attacks
				Result := foundation.secure_compare (l_parts [3], l_expected_sig)
			end
		end

	verify_secure (a_token: STRING): BOOLEAN
			-- Securely verify `a_token' with algorithm validation.
			-- Rejects "none" algorithm and validates algorithm matches HS256.
			-- This is the recommended verification method for production use.
		require
			token_not_void: a_token /= Void
		do
			Result := verify_with_algorithm (a_token, "HS256")
		end

	verify_with_algorithm (a_token: STRING; a_allowed_algorithm: STRING): BOOLEAN
			-- Verify `a_token' and ensure algorithm matches `a_allowed_algorithm'.
			-- CRITICAL: Always use this or `verify_secure' to prevent algorithm attacks.
		require
			token_not_void: a_token /= Void
			algorithm_not_void: a_allowed_algorithm /= Void
			algorithm_not_empty: not a_allowed_algorithm.is_empty
		local
			l_header: detachable JSON_OBJECT
			l_alg: STRING
		do
			-- First check header algorithm
			l_header := decode_header (a_token)
			if attached l_header as h then
				if attached {JSON_STRING} h.item ("alg") as alg_json then
					l_alg := alg_json.unescaped_string_8
					-- Reject "none" algorithm (case-insensitive)
					if not is_none_algorithm (l_alg) then
						-- Verify algorithm matches expected
						if l_alg.same_string (a_allowed_algorithm) then
							-- Now verify signature
							Result := verify (a_token)
						end
					end
				end
			end
		end

	verify_with_expiration (a_token: STRING): BOOLEAN
			-- Verify `a_token' signature and check expiration.
			-- WARNING: Use `verify_full' for production - this does not check algorithm.
		require
			token_not_void: a_token /= Void
		local
			l_claims: detachable JSON_OBJECT
			l_exp: INTEGER_64
			l_now: INTEGER_64
		do
			if verify (a_token) then
				l_claims := decode_claims (a_token)
				if attached l_claims as lc then
					if attached {JSON_NUMBER} lc.item ("exp") as l_exp_json then
						l_exp := l_exp_json.integer_64_item
						l_now := current_unix_time
						Result := l_now <= l_exp + clock_skew
					else
						-- No expiration claim, token is valid
						Result := True
					end
				end
			end
		end

	verify_with_audience (a_token: STRING; a_expected_audience: STRING): BOOLEAN
			-- Verify `a_token' and check audience claim matches `a_expected_audience'.
		require
			token_not_void: a_token /= Void
			audience_not_void: a_expected_audience /= Void
		local
			l_claims: detachable JSON_OBJECT
			i: INTEGER
		do
			if verify_secure (a_token) then
				l_claims := decode_claims (a_token)
				if attached l_claims as lc then
					if attached {JSON_STRING} lc.item ("aud") as l_aud then
						Result := l_aud.unescaped_string_8.same_string (a_expected_audience)
					elseif attached {JSON_ARRAY} lc.item ("aud") as l_aud_array then
						-- Audience can be an array
						from
							i := 1
						until
							i > l_aud_array.count or Result
						loop
							if attached {JSON_STRING} l_aud_array.i_th (i) as aud_str then
								if aud_str.unescaped_string_8.same_string (a_expected_audience) then
									Result := True
								end
							end
							i := i + 1
						variant
							l_aud_array.count - i + 1
						end
					end
				end
			end
		end

	verify_nbf (a_token: STRING): BOOLEAN
			-- Check if `a_token' is valid according to "not before" (nbf) claim.
			-- Returns True if no nbf claim present or if current time >= nbf.
		require
			token_not_void: a_token /= Void
		local
			l_claims: detachable JSON_OBJECT
			l_nbf: INTEGER_64
			l_now: INTEGER_64
		do
			l_claims := decode_claims (a_token)
			if attached l_claims as lc then
				if attached {JSON_NUMBER} lc.item ("nbf") as l_nbf_json then
					l_nbf := l_nbf_json.integer_64_item
					l_now := current_unix_time
					Result := l_now >= l_nbf - clock_skew
				else
					-- No nbf claim, token is valid
					Result := True
				end
			else
				Result := True
			end
		end

	verify_full (a_token: STRING; a_expected_audience: detachable STRING): BOOLEAN
			-- Comprehensive token verification:
			-- 1. Rejects "none" algorithm
			-- 2. Validates algorithm is HS256
			-- 3. Verifies signature (constant-time)
			-- 4. Checks expiration (with clock skew)
			-- 5. Checks not-before (with clock skew)
			-- 6. Optionally validates audience
		require
			token_not_void: a_token /= Void
		local
			l_claims: detachable JSON_OBJECT
			l_exp, l_nbf, l_now: INTEGER_64
			i: INTEGER
		do
			-- Step 1-3: Verify signature with algorithm check
			if verify_secure (a_token) then
				l_claims := decode_claims (a_token)
				if attached l_claims as lc then
					l_now := current_unix_time

					-- Step 4: Check expiration
					if attached {JSON_NUMBER} lc.item ("exp") as l_exp_json then
						l_exp := l_exp_json.integer_64_item
						if l_now > l_exp + clock_skew then
							Result := False
						else
							Result := True
						end
					else
						Result := True
					end

					-- Step 5: Check not-before
					if Result and then attached {JSON_NUMBER} lc.item ("nbf") as l_nbf_json then
						l_nbf := l_nbf_json.integer_64_item
						if l_now < l_nbf - clock_skew then
							Result := False
						end
					end

					-- Step 6: Check audience (if required)
					if Result and then attached a_expected_audience as l_aud_expected then
						if attached {JSON_STRING} lc.item ("aud") as l_aud then
							Result := l_aud.unescaped_string_8.same_string (l_aud_expected)
						elseif attached {JSON_ARRAY} lc.item ("aud") as l_aud_array then
							Result := False
							from
								i := 1
							until
								i > l_aud_array.count or Result
							loop
								if attached {JSON_STRING} l_aud_array.i_th (i) as aud_str then
									if aud_str.unescaped_string_8.same_string (l_aud_expected) then
										Result := True
									end
								end
								i := i + 1
							variant
								l_aud_array.count - i + 1
							end
						else
							-- No audience claim but one was expected
							Result := False
						end
					end
				end
			end
		end

	is_expired (a_token: STRING): BOOLEAN
			-- Is `a_token' expired?
		require
			token_not_void: a_token /= Void
		local
			l_claims: detachable JSON_OBJECT
			l_exp: INTEGER_64
		do
			l_claims := decode_claims (a_token)
			if attached l_claims as lc then
				if attached {JSON_NUMBER} lc.item ("exp") as l_exp_json then
					l_exp := l_exp_json.integer_64_item
					Result := current_unix_time > l_exp + clock_skew
				end
			end
		end

feature -- Token Decoding

	decode_claims (a_token: STRING): detachable JSON_OBJECT
			-- Decode payload claims from `a_token'.
			-- Returns Void if token is malformed.
		require
			token_not_void: a_token /= Void
		local
			l_parts: LIST [STRING]
			l_payload_json: STRING
			l_parser: JSON_PARSER
		do
			l_parts := a_token.split ('.')
			if l_parts.count = 3 then
				l_payload_json := base64_url_decode (l_parts [2])
				create l_parser.make_with_string (l_payload_json)
				l_parser.parse_content
				if l_parser.is_valid and then attached {JSON_OBJECT} l_parser.parsed_json_object as l_obj then
					Result := l_obj
				end
			end
		end

	decode_header (a_token: STRING): detachable JSON_OBJECT
			-- Decode header from `a_token'.
		require
			token_not_void: a_token /= Void
		local
			l_parts: LIST [STRING]
			l_header_json: STRING
			l_parser: JSON_PARSER
		do
			l_parts := a_token.split ('.')
			if l_parts.count >= 1 then
				l_header_json := base64_url_decode (l_parts [1])
				create l_parser.make_with_string (l_header_json)
				l_parser.parse_content
				if l_parser.is_valid and then attached {JSON_OBJECT} l_parser.parsed_json_object as l_obj then
					Result := l_obj
				end
			end
		end

	get_claim (a_token: STRING; a_claim_name: STRING): detachable JSON_VALUE
			-- Get specific claim from `a_token'.
		require
			token_not_void: a_token /= Void
			claim_name_not_void: a_claim_name /= Void
		do
			if attached decode_claims (a_token) as l_claims then
				Result := l_claims.item (a_claim_name)
			end
		end

	get_string_claim (a_token: STRING; a_claim_name: STRING): detachable STRING
			-- Get string claim from `a_token'.
		require
			token_not_void: a_token /= Void
			claim_name_not_void: a_claim_name /= Void
		do
			if attached {JSON_STRING} get_claim (a_token, a_claim_name) as l_str then
				Result := l_str.unescaped_string_8
			end
		end

	get_integer_claim (a_token: STRING; a_claim_name: STRING): INTEGER_64
			-- Get integer claim from `a_token'.
			-- Returns 0 if claim doesn't exist or isn't a number.
		require
			token_not_void: a_token /= Void
			claim_name_not_void: a_claim_name /= Void
		do
			if attached {JSON_NUMBER} get_claim (a_token, a_claim_name) as l_num then
				Result := l_num.integer_64_item
			end
		end

feature -- Token Parts

	extract_header (a_token: STRING): STRING
			-- Extract Base64URL-encoded header from `a_token'.
		require
			token_not_void: a_token /= Void
		local
			l_parts: LIST [STRING]
		do
			l_parts := a_token.split ('.')
			if l_parts.count >= 1 then
				Result := l_parts [1]
			else
				Result := ""
			end
		end

	extract_payload (a_token: STRING): STRING
			-- Extract Base64URL-encoded payload from `a_token'.
		require
			token_not_void: a_token /= Void
		local
			l_parts: LIST [STRING]
		do
			l_parts := a_token.split ('.')
			if l_parts.count >= 2 then
				Result := l_parts [2]
			else
				Result := ""
			end
		end

	extract_signature (a_token: STRING): STRING
			-- Extract Base64URL-encoded signature from `a_token'.
		require
			token_not_void: a_token /= Void
		local
			l_parts: LIST [STRING]
		do
			l_parts := a_token.split ('.')
			if l_parts.count >= 3 then
				Result := l_parts [3]
			else
				Result := ""
			end
		end

feature {NONE} -- Implementation

	secret: STRING
			-- Secret key for HMAC signing.

	algorithm: STRING
			-- Algorithm (currently only HS256).

	foundation: FOUNDATION
			-- Foundation API for encoding, hashing, and UUID generation.

	header_json: STRING
			-- Standard JWT header for HS256.
		do
			Result := "{%"alg%":%"HS256%",%"typ%":%"JWT%"}"
		ensure
			result_not_void: Result /= Void
		end

	create_signature (a_input: STRING): STRING
			-- Create HMAC-SHA256 signature of `a_input', Base64URL encoded.
		require
			input_not_void: a_input /= Void
		local
			l_hmac_bytes: ARRAY [NATURAL_8]
		do
			l_hmac_bytes := foundation.hmac_sha256_bytes (secret, a_input)
			Result := base64_url_encode_bytes (l_hmac_bytes)
		ensure
			result_not_void: Result /= Void
		end

	base64_url_encode (a_input: STRING): STRING
			-- Encode `a_input' as Base64URL (no padding).
		require
			input_not_void: a_input /= Void
		do
			Result := foundation.base64_url_encode (a_input)
		ensure
			result_not_void: Result /= Void
			no_padding: not Result.has ('=')
		end

	base64_url_encode_bytes (a_bytes: ARRAY [NATURAL_8]): STRING
			-- Encode bytes as Base64URL (no padding).
		require
			bytes_not_void: a_bytes /= Void
		local
			l_str: STRING
		do
			-- Convert bytes to string then encode as URL-safe Base64
			create l_str.make (a_bytes.count)
			across a_bytes as b loop
				l_str.append_character (b.item.to_character_8)
			end
			Result := foundation.base64_url_encode (l_str)
		ensure
			result_not_void: Result /= Void
		end

	base64_url_decode (a_input: STRING): STRING
			-- Decode Base64URL `a_input'.
		require
			input_not_void: a_input /= Void
		do
			Result := foundation.base64_url_decode (a_input)
		ensure
			result_not_void: Result /= Void
		end

	is_none_algorithm (a_alg: STRING): BOOLEAN
			-- Is `a_alg' the dangerous "none" algorithm (case-insensitive)?
		require
			alg_not_void: a_alg /= Void
		do
			Result := a_alg.as_lower.same_string ("none")
		end

	current_unix_time: INTEGER_64
			-- Current Unix timestamp in seconds.
		local
			l_date: DATE_TIME
			l_epoch: DATE_TIME
			l_duration: DATE_TIME_DURATION
		do
			create l_date.make_now_utc
			create l_epoch.make (1970, 1, 1, 0, 0, 0)
			l_duration := l_date.relative_duration (l_epoch)
			Result := l_duration.seconds_count
		end

invariant
	secret_exists: secret /= Void
	secret_not_empty: not secret.is_empty
	algorithm_set: algorithm /= Void
	foundation_exists: foundation /= Void
	clock_skew_non_negative: clock_skew >= 0

note
	copyright: "Copyright (c) 2024-2025, Larry Rix"
	license: "MIT License"

end
