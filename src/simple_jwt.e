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

		Usage:
			create jwt.make ("secret-key")
			token := jwt.create_token (claims)
			if jwt.verify (token) then ...
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
			create base64.make
			create hasher.make
			algorithm := "HS256"
		ensure
			secret_set: secret = a_secret
			algorithm_hs256: algorithm.same_string ("HS256")
		end

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

feature -- Token Verification

	verify (a_token: STRING): BOOLEAN
			-- Verify `a_token' signature is valid.
			-- Does NOT check expiration - use `verify_with_expiration' for that.
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
				Result := l_parts [3].same_string (l_expected_sig)
			end
		end

	verify_with_expiration (a_token: STRING): BOOLEAN
			-- Verify `a_token' signature and check expiration.
		require
			token_not_void: a_token /= Void
		local
			l_claims: detachable JSON_OBJECT
			l_exp: INTEGER_64
		do
			if verify (a_token) then
				l_claims := decode_claims (a_token)
				if attached l_claims as lc then
					if attached {JSON_NUMBER} lc.item ("exp") as l_exp_json then
						l_exp := l_exp_json.integer_64_item
						Result := current_unix_time <= l_exp
					else
						-- No expiration claim, token is valid
						Result := True
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
					Result := current_unix_time > l_exp
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

	base64: SIMPLE_BASE64
			-- Base64 encoder/decoder.

	hasher: SIMPLE_HASH
			-- Hash calculator.

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
			l_hmac_bytes := hasher.hmac_sha256_bytes (secret, a_input)
			Result := base64_url_encode_bytes (l_hmac_bytes)
		ensure
			result_not_void: Result /= Void
		end

	base64_url_encode (a_input: STRING): STRING
			-- Encode `a_input' as Base64URL (no padding).
		require
			input_not_void: a_input /= Void
		do
			Result := base64.encode_url (a_input)
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
			-- Convert bytes to string
			create l_str.make (a_bytes.count)
			across a_bytes as b loop
				l_str.append_character (b.item.to_character_8)
			end
			Result := base64.encode_url (l_str)
		ensure
			result_not_void: Result /= Void
		end

	base64_url_decode (a_input: STRING): STRING
			-- Decode Base64URL `a_input'.
		require
			input_not_void: a_input /= Void
		do
			Result := base64.decode_url (a_input)
		ensure
			result_not_void: Result /= Void
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
	base64_exists: base64 /= Void
	hasher_exists: hasher /= Void

note
	copyright: "Copyright (c) 2024-2025, Larry Rix"
	license: "MIT License"

end
