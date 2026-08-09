package authz.mfa_test

import data.authz.mfa

# mfa.rego had no dedicated test file: its only coverage came as a side
# effect of decision_test.rego exercising the combined authz.decision rule,
# never a deliberate, isolated test of mfa.mfa_verified's own logic (found
# in a cross-service/cross-file audit alongside the decision.rego and
# rbac.rego coverage gaps -- those two turned out to already be fixed by an
# earlier change; this one was real).
#
# 2026-08: extended for the sensitive-action grace-window finding -- a
# single TOTP used to unlock a 5-minute blank check for every subsequent
# sensitive action, not just the one actually challenged. input.mfa now
# carries two raw booleans (ticket_verified/grace_verified) instead of one
# pre-combined "verified" -- see mfa.rego and CLAUDE.md.

test_ticket_verified_true_grants_mfa_verified_even_when_sensitive if {
	mfa.mfa_verified with input as {
		"mfa": {"ticket_verified": true, "grace_verified": false},
		"resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
	}
}

test_grace_verified_true_grants_mfa_verified_when_not_sensitive if {
	mfa.mfa_verified with input as {
		"mfa": {"ticket_verified": false, "grace_verified": true},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
	}
}

# The core regression test for the finding: grace alone must NOT be enough
# for a sensitive action, no matter how recently any other TOTP was solved.
test_grace_verified_alone_does_not_grant_mfa_verified_when_sensitive if {
	not mfa.mfa_verified with input as {
		"mfa": {"ticket_verified": false, "grace_verified": true},
		"resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
	}
}

test_grace_verified_alone_does_not_grant_mfa_verified_for_users_create if {
	not mfa.mfa_verified with input as {
		"mfa": {"ticket_verified": false, "grace_verified": true},
		"resource": {"http_method": "POST", "route": "/users", "action": "create"},
	}
}

test_neither_ticket_nor_grace_denies if {
	not mfa.mfa_verified with input as {
		"mfa": {"ticket_verified": false, "grace_verified": false},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
	}
}

test_mfa_verified_false_when_mfa_absent if {
	not mfa.mfa_verified with input as {"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"}}
}

# Type-confusion defense in depth, same class of guard as decision.rego's
# malformed_score/threshold tests and adaptive_access.rego's is_number
# checks: Rego's `==` is strict-type equality, so a stringly-typed "true"
# must NOT satisfy `input.mfa.ticket_verified == true` -- if it ever did, a
# caller that (bug or not) sent it as a string would silently pass MFA.
test_mfa_verified_false_when_ticket_verified_is_a_string if {
	not mfa.mfa_verified with input as {
		"mfa": {"ticket_verified": "true", "grace_verified": false},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
	}
}

test_mfa_verified_false_when_grace_verified_is_a_string if {
	not mfa.mfa_verified with input as {
		"mfa": {"ticket_verified": false, "grace_verified": "true"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
	}
}
