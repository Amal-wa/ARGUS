package authz.mfa_test

import data.authz.mfa

# mfa.rego had no dedicated test file: its only coverage came as a side
# effect of decision_test.rego exercising the combined authz.decision rule,
# never a deliberate, isolated test of mfa.mfa_verified's own logic (found
# in a cross-service/cross-file audit alongside the decision.rego and
# rbac.rego coverage gaps -- those two turned out to already be fixed by an
# earlier change; this one was real).

test_mfa_verified_true_when_input_verified_true if {
	mfa.mfa_verified with input as {"mfa": {"verified": true}}
}

test_mfa_verified_false_when_input_verified_false if {
	not mfa.mfa_verified with input as {"mfa": {"verified": false}}
}

test_mfa_verified_false_when_mfa_absent if {
	not mfa.mfa_verified with input as {}
}

# Type-confusion defense in depth, same class of guard as decision.rego's
# malformed_score/threshold tests and adaptive_access.rego's is_number
# checks: Rego's `==` is strict-type equality, so a stringly-typed "true"
# must NOT satisfy `input.mfa.verified == true` -- if it ever did, a caller
# that (bug or not) sent verified as a string would silently pass MFA.
test_mfa_verified_false_when_verified_is_a_string if {
	not mfa.mfa_verified with input as {"mfa": {"verified": "true"}}
}
