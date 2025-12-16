note
	description: "[
		Zero-configuration JWT facade for beginners.

		One-liner token operations - no crypto knowledge required.
		For full control, use SIMPLE_JWT directly.

		Quick Start Examples:
			create jwt.make ("your-secret-key-at-least-32-chars")

			-- Create a token for user
			token := jwt.create_for_user ("user123")

			-- Create token with expiration (24 hours)
			token := jwt.create_with_expiry ("user123", 24)

			-- Verify token
			if jwt.is_valid (token) then
				print ("User: " + jwt.get_user_id (token))
			end

			-- Check expiration
			if jwt.is_expired (token) then
				print ("Token expired!")
			end
	]"
	author: "Larry Rix"
	date: "$Date$"
	revision: "$Revision$"

class
	SIMPLE_JWT_QUICK

create
	make

feature {NONE} -- Initialization

	make (a_secret: STRING)
			-- Create JWT handler with secret key.
			-- Secret should be at least 32 characters for security.
		require
			secret_not_empty: not a_secret.is_empty
			secret_length: a_secret.count >= 16
		do
			create jwt.make (a_secret)
			jwt.set_clock_skew (60)  -- 1 minute tolerance for distributed systems
			create logger.make ("jwt_quick")
			logger.debug_log ("JWT handler initialized")
		ensure
			jwt_exists: jwt /= Void
		end

feature -- Token Creation

	create_for_user (a_user_id: STRING): STRING
			-- Create token for user with no expiration.
		require
			user_id_not_empty: not a_user_id.is_empty
		local
			l_claims: JSON_OBJECT
		do
			create l_claims.make_empty
			l_claims.put_string (a_user_id, "sub")
			l_claims.put_integer (current_timestamp, "iat")
			Result := jwt.create_token (l_claims)
			logger.debug_log ("Created token for user: " + a_user_id)
		ensure
			token_created: not Result.is_empty
			has_three_parts: Result.occurrences ('.') = 2
		end

	create_with_expiry (a_user_id: STRING; a_hours: INTEGER): STRING
			-- Create token for user that expires in specified hours.
		require
			user_id_not_empty: not a_user_id.is_empty
			positive_hours: a_hours > 0
		local
			l_claims: JSON_OBJECT
			l_exp: INTEGER_64
		do
			l_exp := current_timestamp + (a_hours * 3600)
			create l_claims.make_empty
			l_claims.put_string (a_user_id, "sub")
			l_claims.put_integer (current_timestamp, "iat")
			l_claims.put (create {JSON_NUMBER}.make_integer (l_exp.to_integer_32), "exp")
			Result := jwt.create_token (l_claims)
			logger.debug_log ("Created token for user: " + a_user_id + " (expires in " + a_hours.out + "h)")
		ensure
			token_created: not Result.is_empty
			has_three_parts: Result.occurrences ('.') = 2
		end

	create_with_data (a_user_id: STRING; a_data: STRING_TABLE [STRING]; a_hours: INTEGER): STRING
			-- Create token with custom data.
			-- Example: jwt.create_with_data ("user123", <<"role", "admin">>, 24)
		require
			user_id_not_empty: not a_user_id.is_empty
			positive_hours: a_hours > 0
		local
			l_claims: JSON_OBJECT
			l_exp: INTEGER_64
		do
			l_exp := current_timestamp + (a_hours * 3600)
			create l_claims.make_empty
			l_claims.put_string (a_user_id, "sub")
			l_claims.put_integer (current_timestamp, "iat")
			l_claims.put (create {JSON_NUMBER}.make_integer (l_exp.to_integer_32), "exp")

			-- Add custom data
			across a_data as item loop
				l_claims.put_string (item, item.key)
			end

			Result := jwt.create_token (l_claims)
			logger.debug_log ("Created token with custom data for user: " + a_user_id)
		ensure
			token_created: not Result.is_empty
		end

feature -- Token Verification

	is_valid (a_token: STRING): BOOLEAN
			-- Is token valid (signature OK and not expired)?
			-- Use this for authentication checks.
		require
			token_not_empty: not a_token.is_empty
		do
			Result := jwt.verify_secure (a_token)
			if Result then
				logger.debug_log ("Token valid")
			else
				logger.debug_log ("Token invalid: " + jwt.last_error.out)
			end
		end

	is_expired (a_token: STRING): BOOLEAN
			-- Has token expired?
		require
			token_not_empty: not a_token.is_empty
		local
			l_claims: detachable JSON_OBJECT
			l_exp: INTEGER_64
		do
			l_claims := jwt.decode_payload (a_token)
			if attached l_claims as c and then attached {JSON_NUMBER} c.item ("exp") as exp then
				l_exp := exp.integer_64_item
				Result := current_timestamp > l_exp
			end
		end

feature -- Token Data Extraction

	get_user_id (a_token: STRING): STRING
			-- Extract user ID from token.
			-- Returns empty string if token invalid or no user ID.
		require
			token_not_empty: not a_token.is_empty
		local
			l_claims: detachable JSON_OBJECT
		do
			l_claims := jwt.decode_payload (a_token)
			if attached l_claims as c and then attached {JSON_STRING} c.item ("sub") as sub then
				Result := sub.unescaped_string_8
			else
				Result := ""
			end
		ensure
			result_exists: Result /= Void
		end

	get_claim (a_token: STRING; a_claim_name: STRING): detachable STRING
			-- Extract custom claim from token.
		require
			token_not_empty: not a_token.is_empty
			claim_name_not_empty: not a_claim_name.is_empty
		local
			l_claims: detachable JSON_OBJECT
		do
			l_claims := jwt.decode_payload (a_token)
			if attached l_claims as c and then attached {JSON_STRING} c.item (a_claim_name) as val then
				Result := val.unescaped_string_8
			end
		end

	get_expiration (a_token: STRING): INTEGER_64
			-- Get expiration timestamp from token (Unix epoch seconds).
			-- Returns 0 if no expiration or invalid token.
		require
			token_not_empty: not a_token.is_empty
		local
			l_claims: detachable JSON_OBJECT
		do
			l_claims := jwt.decode_payload (a_token)
			if attached l_claims as c and then attached {JSON_NUMBER} c.item ("exp") as exp then
				Result := exp.integer_64_item
			end
		end

feature -- Status

	last_error: STRING
			-- Error message from last verification failure.
		do
			Result := jwt.last_error.out
		ensure
			result_exists: Result /= Void
		end

feature -- Advanced Access

	jwt: SIMPLE_JWT
			-- Access underlying JWT handler for advanced operations.

feature {NONE} -- Implementation

	logger: SIMPLE_LOGGER
			-- Logger for debugging.

	current_timestamp: INTEGER_64
			-- Current Unix timestamp in seconds.
		local
			l_dt: SIMPLE_DATE_TIME
		do
			create l_dt.make_now
			Result := l_dt.to_timestamp
		end

invariant
	jwt_exists: jwt /= Void
	logger_exists: logger /= Void

end
