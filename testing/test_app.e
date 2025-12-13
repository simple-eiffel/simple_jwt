note
	description: "Test application for simple_jwt"
	author: "Larry Rix"

class
	TEST_APP

create
	make

feature {NONE} -- Initialization

	make
			-- Run tests.
		do
			create tests
			print ("simple_jwt test runner%N")
			print ("========================%N%N")

			passed := 0
			failed := 0

			-- Token Creation
			run_test (agent tests.test_create_token_basic, "test_create_token_basic")
			run_test (agent tests.test_create_token_with_claims, "test_create_token_with_claims")
			run_test (agent tests.test_create_token_with_custom_claims, "test_create_token_with_custom_claims")
			run_test (agent tests.test_create_token_with_jti, "test_create_token_with_jti")

			-- Token Verification
			run_test (agent tests.test_verify_valid_token, "test_verify_valid_token")
			run_test (agent tests.test_verify_invalid_signature, "test_verify_invalid_signature")
			run_test (agent tests.test_verify_tampered_payload, "test_verify_tampered_payload")
			run_test (agent tests.test_verify_with_expiration_valid, "test_verify_with_expiration_valid")
			run_test (agent tests.test_verify_with_expiration_no_exp, "test_verify_with_expiration_no_exp")
			run_test (agent tests.test_verify_secure_valid_token, "test_verify_secure_valid_token")
			run_test (agent tests.test_verify_with_algorithm_correct, "test_verify_with_algorithm_correct")
			run_test (agent tests.test_verify_with_algorithm_mismatch, "test_verify_with_algorithm_mismatch")
			run_test (agent tests.test_verify_rejects_none_algorithm, "test_verify_rejects_none_algorithm")
			run_test (agent tests.test_verify_rejects_none_algorithm_case_variations, "test_verify_rejects_none_algorithm_case_variations")

			-- Clock Skew
			run_test (agent tests.test_clock_skew_default_zero, "test_clock_skew_default_zero")
			run_test (agent tests.test_set_clock_skew, "test_set_clock_skew")

			-- Audience
			run_test (agent tests.test_verify_with_audience_match, "test_verify_with_audience_match")
			run_test (agent tests.test_verify_with_audience_mismatch, "test_verify_with_audience_mismatch")
			run_test (agent tests.test_verify_with_audience_array, "test_verify_with_audience_array")

			-- Not Before
			run_test (agent tests.test_verify_nbf_no_claim, "test_verify_nbf_no_claim")
			run_test (agent tests.test_verify_nbf_valid, "test_verify_nbf_valid")

			-- Full Verification
			run_test (agent tests.test_verify_full_valid_token, "test_verify_full_valid_token")
			run_test (agent tests.test_verify_full_wrong_audience, "test_verify_full_wrong_audience")
			run_test (agent tests.test_verify_full_no_audience_required, "test_verify_full_no_audience_required")

			-- Decoding
			run_test (agent tests.test_decode_claims, "test_decode_claims")
			run_test (agent tests.test_decode_header, "test_decode_header")
			run_test (agent tests.test_get_string_claim, "test_get_string_claim")
			run_test (agent tests.test_get_integer_claim, "test_get_integer_claim")

			-- Extraction
			run_test (agent tests.test_extract_header, "test_extract_header")
			run_test (agent tests.test_extract_payload, "test_extract_payload")
			run_test (agent tests.test_extract_signature, "test_extract_signature")

			-- Expiration
			run_test (agent tests.test_is_expired_false, "test_is_expired_false")
			run_test (agent tests.test_is_expired_no_exp_claim, "test_is_expired_no_exp_claim")

			-- Consistency
			run_test (agent tests.test_same_input_same_output, "test_same_input_same_output")
			run_test (agent tests.test_different_secrets_different_tokens, "test_different_secrets_different_tokens")

			print ("%N========================%N")
			print ("Results: " + passed.out + " passed, " + failed.out + " failed%N")

			if failed > 0 then
				print ("TESTS FAILED%N")
			else
				print ("ALL TESTS PASSED%N")
			end
		end

feature {NONE} -- Implementation

	tests: LIB_TESTS

	passed: INTEGER
	failed: INTEGER

	run_test (a_test: PROCEDURE; a_name: STRING)
			-- Run a single test and update counters.
		local
			l_retried: BOOLEAN
		do
			if not l_retried then
				a_test.call (Void)
				print ("  PASS: " + a_name + "%N")
				passed := passed + 1
			end
		rescue
			print ("  FAIL: " + a_name + "%N")
			failed := failed + 1
			l_retried := True
			retry
		end

end
